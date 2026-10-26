//! SBc-AP transport toward the CBC (#1071, TS 29.168 §4.1).
//!
//! TS 29.168 §4.1.3: SCTP, port 29168, PPID 24, and "The CBC shall establish the
//! SCTP association", so the MME listens. The listener mirrors the S1-MME one
//! (`s1ap_path`: the kernel-SCTP backend behind the `kernel-sctp` feature), with
//! the exposure kept to what the operator configured:
//! - **Off by default.** No `mme.sbcap` block means no socket. There is no default
//!   bind address, wildcard or other; a configured `0.0.0.0` / `::` is bound but
//!   warned about at startup.
//! - **Allowlist.** Only the configured CBC addresses (`mme.sbcap.cbc`) may hold an
//!   association. Any other peer gets an SCTP ABORT, counted
//!   (`mme_sbcap_refused_associations_total{reason="peer"}`), with a rate-limited
//!   log. An `sbcap` block with no CBC is not bound.
//! - **Bounded.** At most `max_associations` (default 4) CBC associations; one more
//!   is aborted (`reason="limit"`). A message longer than [`SBCAP_MAX_MESSAGE`] is
//!   dropped before decode (`mme_sbcap_oversized_messages_total`).
//!
//! SBc-AP has no application-layer authentication. Its protection is the
//! network domain security of TS 33.210 (NDS/IP: IPsec on Za/Zb, or a private
//! network), as for S1-MME; the allowlist only keeps unconfigured peers off.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use tokio::sync::mpsc;

use crate::context::MmeContext;

/// The registered SBc-AP port (TS 29.168 §4.1.3).
pub const SBCAP_PORT: u16 = nextgcore_sbcap_gen::SBCAP_PORT;
/// The registered SBc-AP payload protocol identifier (TS 29.168 §4.1.3).
pub const SBCAP_PPID: u32 = nextgcore_sbcap_gen::SBCAP_PPID;
/// The default bound on CBC associations: TS 29.168 §4.1.3 wants several
/// simultaneous associations supported (multiple CBC endpoints), not many.
pub const DEFAULT_MAX_ASSOCIATIONS: usize = 4;
/// The largest SBc-AP message decoded. The biggest legitimate one is a
/// WRITE-REPLACE WARNING REQUEST with 9600 octets of content and a long TAI or
/// cell list; 64 KiB covers it with room.
pub const SBCAP_MAX_MESSAGE: usize = 65536;
/// SCTP stream for SBc-AP (non-UE-associated signalling only).
const SBCAP_STREAM_ID: u16 = 0;

/// `mme.sbcap`, as configuration resolved it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SbcapConfig {
    /// The one address the listener binds.
    pub server: SocketAddr,
    /// The CBC addresses allowed to associate.
    pub cbc: Vec<IpAddr>,
    /// The bound on simultaneous CBC associations.
    pub max_associations: usize,
}

/// Associations refused because the peer is not a configured CBC.
pub static REFUSED_PEER_TOTAL: AtomicU64 = AtomicU64::new(0);
/// Associations refused because `max_associations` were up.
pub static REFUSED_LIMIT_TOTAL: AtomicU64 = AtomicU64::new(0);
/// Messages dropped before decode for their size.
pub static OVERSIZED_TOTAL: AtomicU64 = AtomicU64::new(0);
/// SBc-AP PDUs received from a CBC and handled.
pub static RECEIVED_TOTAL: AtomicU64 = AtomicU64::new(0);

/// MME-originated SBc-AP messages (PWS Restart / Failure Indication) sent to the
/// CBC associations, and those no association took.
pub static INDICATIONS_SENT_TOTAL: AtomicU64 = AtomicU64::new(0);
pub static INDICATIONS_UNSENT_TOTAL: AtomicU64 = AtomicU64::new(0);

/// The queue the MME's own SBc-AP messages take to the server, from the
/// synchronous S1AP handlers. Installed by each [`SbcapServer::bind`] (one server
/// per process in production); `None` when SBc-AP is not configured.
static INDICATIONS: Mutex<Option<mpsc::UnboundedSender<Vec<u8>>>> = Mutex::new(None);

/// Serialises the tests that bind a server, since each bind replaces
/// [`INDICATIONS`]. Declared beside it.
#[cfg(test)]
pub(crate) static SERVER_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Send an MME-originated SBc-AP PDU to every CBC association (TS 29.168
/// §4.3.3E / §4.3.3F; TS 23.007 §15A.1.2 has the eNB's restart reach the CBC
/// through the MME). Returns whether the transport took it; `what` names it in
/// the log when it did not.
pub fn indicate_to_cbc(pdu: Vec<u8>, what: &str) -> bool {
    let tx = INDICATIONS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    let taken = tx.is_some_and(|tx| tx.send(pdu).is_ok());
    if !taken {
        INDICATIONS_UNSENT_TOTAL.fetch_add(1, Ordering::Relaxed);
        log::warn!("{what}: SBc-AP is not configured (mme.sbcap), so the CBC is not told");
    }
    taken
}

/// The SBc-AP counters, Prometheus text.
pub fn render_metrics() -> String {
    format!(
        "# HELP mme_sbcap_refused_associations_total SBc-AP associations aborted: not a \
         configured CBC (peer) or max_associations reached (limit)\n\
         # TYPE mme_sbcap_refused_associations_total counter\n\
         mme_sbcap_refused_associations_total{{reason=\"peer\"}} {}\n\
         mme_sbcap_refused_associations_total{{reason=\"limit\"}} {}\n\
         # HELP mme_sbcap_oversized_messages_total SBc-AP messages dropped before decode for \
         their size\n\
         # TYPE mme_sbcap_oversized_messages_total counter\n\
         mme_sbcap_oversized_messages_total {}\n\
         # HELP mme_sbcap_received_total SBc-AP PDUs received from a CBC\n\
         # TYPE mme_sbcap_received_total counter\n\
         mme_sbcap_received_total {}\n\
         # HELP mme_sbcap_indications_total PWS Restart / Failure Indications for the CBC: \
         sent on its associations, or not (SBc-AP not configured, no association)\n\
         # TYPE mme_sbcap_indications_total counter\n\
         mme_sbcap_indications_total{{result=\"sent\"}} {}\n\
         mme_sbcap_indications_total{{result=\"unsent\"}} {}\n",
        REFUSED_PEER_TOTAL.load(Ordering::Relaxed),
        REFUSED_LIMIT_TOTAL.load(Ordering::Relaxed),
        OVERSIZED_TOTAL.load(Ordering::Relaxed),
        RECEIVED_TOTAL.load(Ordering::Relaxed),
        INDICATIONS_SENT_TOTAL.load(Ordering::Relaxed),
        INDICATIONS_UNSENT_TOTAL.load(Ordering::Relaxed),
    )
}

/// The refusal log's limiter: a flood of unknown peers must not flood the log.
/// One process-global, declared beside the counters it logs.
static REFUSAL_LOG: Mutex<Option<nextgcore_sctp::ootb::OotbLimiter>> = Mutex::new(None);

fn log_refusal(what: std::fmt::Arguments<'_>) {
    let now = std::time::Instant::now();
    let mut guard = REFUSAL_LOG.lock().unwrap_or_else(|e| e.into_inner());
    let limiter = guard.get_or_insert_with(|| nextgcore_sctp::ootb::OotbLimiter::new(5, 1, now));
    if limiter.allow(now) {
        log::warn!(
            "{what} ({} similar refusal(s) not logged)",
            limiter.suppressed
        );
    }
}

/// Whether `addr` is a wildcard: bound, but every interface.
pub fn is_wildcard(addr: &SocketAddr) -> bool {
    addr.ip().is_unspecified()
}

/// Count and log one refused association (the transport aborted it).
#[cfg_attr(not(feature = "kernel-sctp"), allow(dead_code))]
fn on_refused(peer: SocketAddr, by_limit: bool) {
    let reason = if by_limit {
        REFUSED_LIMIT_TOTAL.fetch_add(1, Ordering::Relaxed);
        "max_associations reached"
    } else {
        REFUSED_PEER_TOTAL.fetch_add(1, Ordering::Relaxed);
        "not a configured CBC"
    };
    log_refusal(format_args!(
        "SBc-AP association from {peer} aborted (SCTP ABORT): {reason}"
    ));
}

enum Backend {
    #[cfg(feature = "kernel-sctp")]
    Kernel(Box<nextgcore_sctp::KernelSctpServer>),
    Disabled,
}

/// The SBc-AP server: the listener and the CBC associations.
pub struct SbcapServer {
    backend: Backend,
    events: mpsc::UnboundedReceiver<nextgcore_sctp::ServerEvent>,
    _event_tx: mpsc::UnboundedSender<nextgcore_sctp::ServerEvent>,
    /// MME-originated PDUs for every CBC association ([`indicate_to_cbc`]).
    indications: mpsc::UnboundedReceiver<Vec<u8>>,
    config: SbcapConfig,
    /// Admitted associations, by id, with their peer.
    cbcs: HashMap<u64, SocketAddr>,
    local_addr: Option<SocketAddr>,
    ctx: &'static MmeContext,
}

impl SbcapServer {
    /// Bind the SBc-AP listener on `config.server` only.
    pub async fn bind(config: SbcapConfig, ctx: &'static MmeContext) -> anyhow::Result<Self> {
        let (event_tx, events) = mpsc::unbounded_channel();
        if is_wildcard(&config.server) {
            log::warn!(
                "mme.sbcap.server is the wildcard {}: SBc-AP listens on every interface. \
                 Configure the MME's address on the CBC network instead (TS 33.210 NDS/IP)",
                config.server
            );
        }

        #[cfg(feature = "kernel-sctp")]
        let (backend, local_addr) = {
            let sctp = nextgcore_sctp::SctpServerConfig {
                ppid: SBCAP_PPID,
                max_message_size: SBCAP_MAX_MESSAGE as u32,
                ..Default::default()
            };
            let mut server = nextgcore_sctp::KernelSctpServer::bind(config.server, sctp)
                .await
                .map_err(|e| {
                    anyhow::anyhow!(
                        "failed to bind SBc-AP SCTP socket on {}: {e}",
                        config.server
                    )
                })?;
            let bound = server.local_addr();
            // Refused at accept, before the association reaches this layer: an
            // SCTP ABORT (SO_LINGER 0), counted and logged by `on_refused`.
            server.set_admission(nextgcore_sctp::Admission {
                allowed_peers: config.cbc.clone(),
                max_associations: config.max_associations,
                on_refused: std::sync::Arc::new(|peer, refusal| {
                    on_refused(peer, refusal == nextgcore_sctp::Refusal::Limit)
                }),
            });
            server.set_event_sender(event_tx.clone());
            log::info!(
                "SBc-AP SCTP server listening on {bound} (PPID {SBCAP_PPID}), CBC peers {:?}, \
                 at most {} association(s)",
                config.cbc,
                config.max_associations
            );
            (Backend::Kernel(Box::new(server)), Some(bound))
        };

        #[cfg(not(feature = "kernel-sctp"))]
        let (backend, local_addr) = {
            log::warn!(
                "SBc-AP transport unavailable: nextgcore-mmed was built without the \
                 `kernel-sctp` feature, so nothing listens on {}",
                config.server
            );
            (Backend::Disabled, None)
        };

        let (indication_tx, indications) = mpsc::unbounded_channel();
        *INDICATIONS.lock().unwrap_or_else(|e| e.into_inner()) = Some(indication_tx);

        Ok(Self {
            backend,
            events,
            _event_tx: event_tx,
            indications,
            config,
            cbcs: HashMap::new(),
            local_addr,
            ctx,
        })
    }

    /// The bound address, or `None` when the transport is disabled.
    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.local_addr
    }

    /// Admitted CBC associations.
    pub fn num_associations(&self) -> usize {
        self.cbcs.len()
    }

    /// Handle the next transport event, or send the next MME-originated PDU.
    /// Cancel-safe: both arms are `mpsc::recv`.
    pub async fn poll_once(&mut self) {
        tokio::select! {
            event = self.events.recv() => {
                if let Some(event) = event {
                    self.handle_event(event).await;
                }
            }
            pdu = self.indications.recv() => {
                if let Some(pdu) = pdu {
                    self.indicate(&pdu).await;
                }
            }
        }
    }

    /// Send `pdu` on every CBC association.
    async fn indicate(&mut self, pdu: &[u8]) {
        if self.cbcs.is_empty() {
            INDICATIONS_UNSENT_TOTAL.fetch_add(1, Ordering::Relaxed);
            log::warn!(
                "SBc-AP indication ({} octets) not sent: no CBC association is up",
                pdu.len()
            );
            return;
        }
        let ids: Vec<u64> = self.cbcs.keys().copied().collect();
        for id in ids {
            self.send(id, pdu).await;
        }
        INDICATIONS_SENT_TOTAL.fetch_add(1, Ordering::Relaxed);
    }

    async fn handle_event(&mut self, event: nextgcore_sctp::ServerEvent) {
        use nextgcore_sctp::ServerEvent;
        match event {
            ServerEvent::NewAssociation {
                association_id,
                remote_addr,
            } => {
                // Only an admitted CBC gets here (the transport's admission).
                self.cbcs.insert(association_id, remote_addr);
                log::info!("SBc-AP association up from CBC {remote_addr} (assoc={association_id})");
            }
            ServerEvent::DataReceived {
                association_id,
                message,
            } => {
                if !self.cbcs.contains_key(&association_id) {
                    // An association being aborted: nothing from it is read.
                    return;
                }
                if message.data.len() > SBCAP_MAX_MESSAGE {
                    OVERSIZED_TOTAL.fetch_add(1, Ordering::Relaxed);
                    log_refusal(format_args!(
                        "SBc-AP message of {} octets from assoc {association_id} dropped \
                         (limit {SBCAP_MAX_MESSAGE})",
                        message.data.len()
                    ));
                    return;
                }
                RECEIVED_TOTAL.fetch_add(1, Ordering::Relaxed);
                for answer in crate::sbcap_handler::handle_sbcap_pdu(self.ctx, &message.data) {
                    self.send(association_id, &answer).await;
                }
            }
            ServerEvent::AssociationRestarted { association_id } => {
                log::warn!("SBc-AP association {association_id} restarted by the CBC");
            }
            ServerEvent::AssociationClosed {
                association_id,
                reason,
            } => {
                if let Some(peer) = self.cbcs.remove(&association_id) {
                    log::info!(
                        "SBc-AP association with CBC {peer} down (assoc={association_id}): \
                         {reason}"
                    );
                }
            }
        }
    }

    async fn send(&mut self, association_id: u64, pdu: &[u8]) {
        match &mut self.backend {
            #[cfg(feature = "kernel-sctp")]
            Backend::Kernel(server) => {
                if let Err(e) = server.send(association_id, SBCAP_STREAM_ID, pdu).await {
                    log::error!("SBc-AP send to assoc {association_id} failed: {e}");
                }
            }
            Backend::Disabled => {
                let _ = (association_id, pdu);
            }
        }
    }

    /// Stop the listener and drop the associations; the MME's indications are no
    /// longer queued.
    pub fn stop(&mut self) {
        *INDICATIONS.lock().unwrap_or_else(|e| e.into_inner()) = None;
        match &mut self.backend {
            #[cfg(feature = "kernel-sctp")]
            Backend::Kernel(server) => server.stop(),
            Backend::Disabled => {}
        }
        self.cbcs.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(cbc: &[&str], max: usize) -> SbcapConfig {
        SbcapConfig {
            server: "127.0.0.1:0".parse().unwrap(),
            cbc: cbc.iter().map(|a| a.parse().unwrap()).collect(),
            max_associations: max,
        }
    }

    /// Only a configured CBC is admitted, and only up to the bound; an
    /// IPv4-mapped IPv6 peer is its IPv4 address.
    #[cfg(feature = "kernel-sctp")]
    #[test]
    fn only_configured_cbcs_are_admitted_up_to_the_bound() {
        use nextgcore_sctp::Refusal;
        let c = config(&["10.0.0.9", "fd00::9"], 2);
        let a = nextgcore_sctp::Admission {
            allowed_peers: c.cbc.clone(),
            max_associations: c.max_associations,
            on_refused: std::sync::Arc::new(|_, _| {}),
        };
        assert_eq!(a.check("10.0.0.9".parse().unwrap(), 0), None);
        assert_eq!(a.check("fd00::9".parse().unwrap(), 1), None);
        assert_eq!(a.check("::ffff:10.0.0.9".parse().unwrap(), 0), None);
        assert_eq!(a.check("10.0.0.8".parse().unwrap(), 0), Some(Refusal::Peer));
        assert_eq!(
            a.check("10.0.0.9".parse().unwrap(), 2),
            Some(Refusal::Limit)
        );
    }

    #[test]
    fn the_wildcards_are_recognised() {
        assert!(is_wildcard(&"0.0.0.0:29168".parse().unwrap()));
        assert!(is_wildcard(&"[::]:29168".parse().unwrap()));
        assert!(!is_wildcard(&"10.0.0.5:29168".parse().unwrap()));
    }

    #[test]
    fn the_registered_port_and_ppid_are_ts_29_168_s_4_1_3() {
        assert_eq!(SBCAP_PORT, 29168);
        assert_eq!(SBCAP_PPID, 24);
        assert_eq!(nextgcore_sctp::NEXTGCORE_SCTP_SBCAP_PPID, 24);
    }

    #[cfg(all(feature = "kernel-sctp", target_os = "linux"))]
    mod wire {
        use super::*;
        use std::time::Duration;

        fn static_ctx() -> &'static MmeContext {
            let ctx = MmeContext::new();
            ctx.init();
            Box::leak(Box::new(ctx))
        }

        async fn drive(server: &mut SbcapServer, until: impl Fn(&SbcapServer) -> bool) {
            for _ in 0..150 {
                tokio::time::timeout(Duration::from_millis(20), server.poll_once())
                    .await
                    .ok();
                if until(server) {
                    return;
                }
            }
        }

        /// A WRITE-REPLACE WARNING REQUEST without the Repetition Period, so the
        /// answer (cause 6) needs no eNB.
        fn request() -> Vec<u8> {
            use g::Write_Replace_Warning_RequestProtocolIEs_EntryValue as V;
            use nextgcore_sbcap_gen::generated as g;
            let bits = |v: u16| {
                bitvec::vec::BitVec::<u8, bitvec::order::Msb0>::from_slice(&v.to_be_bytes())
            };
            let entry = |id: u16, value: V| g::Write_Replace_Warning_RequestProtocolIEs_Entry {
                id: g::ProtocolIE_ID(id),
                criticality: g::Criticality(g::Criticality::REJECT),
                value,
            };
            nextgcore_sbcap_gen::encode(&g::SBC_AP_PDU::InitiatingMessage(g::InitiatingMessage {
                procedure_code: g::ProcedureCode(0),
                criticality: g::Criticality(g::Criticality::REJECT),
                value: g::InitiatingMessageValue::Id_Write_Replace_Warning(
                    g::Write_Replace_Warning_Request {
                        protocol_i_es: g::Write_Replace_Warning_RequestProtocolIEs(vec![
                            entry(
                                5,
                                V::Id_Message_Identifier(g::Message_Identifier(bits(0x1112))),
                            ),
                            entry(11, V::Id_Serial_Number(g::Serial_Number(bits(0x3001)))),
                        ]),
                        protocol_extensions: None,
                    },
                ),
            }))
            .unwrap()
        }

        /// (data, PPID) of the next user message, skipping notifications; `None`
        /// when the association went away instead.
        fn recv(client: &nextgcore_sctp::KernelSctpSocket) -> Option<(Vec<u8>, u32)> {
            for _ in 0..16 {
                let mut buf = vec![0u8; 8192];
                let (n, info, flags) = client.recv_msg(&mut buf).ok()?;
                if n == 0 {
                    return None;
                }
                if flags & nextgcore_sctp::MSG_NOTIFICATION != 0 {
                    // SCTP_ASSOC_CHANGE with COMM_LOST: the ABORT arrived.
                    // `<linux/sctp.h>`: SCTP_ASSOC_CHANGE is SCTP_SN_TYPE_BASE + 1.
                    let kind = u16::from_ne_bytes([buf[0], buf[1]]) & 0x7fff;
                    let state = u16::from_ne_bytes([buf[8], buf[9]]);
                    if kind == 1 && state == nextgcore_sctp::kernel::SCTP_COMM_LOST {
                        return None;
                    }
                    continue;
                }
                buf.truncate(n);
                return Some((buf, info.ppid));
            }
            None
        }

        /// TS 29.168 §4.1.3: a configured CBC associates, its request is answered
        /// on PPID 24 (here WRITE-REPLACE WARNING RESPONSE, cause 6); a message over
        /// the size bound is dropped before decode and counted.
        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn a_configured_cbc_is_answered_on_ppid_24() {
            let _guard = SERVER_TEST_LOCK.lock().await;
            let mut server = SbcapServer::bind(config(&["127.0.0.1"], 4), static_ctx())
                .await
                .unwrap();
            let bound = server.local_addr().unwrap();
            let client = tokio::task::spawn_blocking(move || {
                nextgcore_sctp::KernelSctpSocket::client(bound, None).unwrap()
            })
            .await
            .unwrap();
            drive(&mut server, |s| s.num_associations() == 1).await;
            assert_eq!(server.num_associations(), 1);

            let oversized_before = OVERSIZED_TOTAL.load(Ordering::Relaxed);
            let big = vec![0u8; SBCAP_MAX_MESSAGE + 1];
            tokio::task::block_in_place(|| {
                client.send(&big, SBCAP_PPID, 0).unwrap();
                client.send(&request(), SBCAP_PPID, 0).unwrap();
            });
            let mut answer = None;
            for _ in 0..10 {
                drive(&mut server, |_| false).await;
                if OVERSIZED_TOTAL.load(Ordering::Relaxed) > oversized_before {
                    answer = Some(());
                    break;
                }
            }
            assert!(answer.is_some(), "the oversized message is counted");
            let (pdu, ppid) = tokio::task::spawn_blocking(move || recv(&client))
                .await
                .unwrap()
                .expect("the answer");
            assert_eq!(ppid, SBCAP_PPID);
            assert!(matches!(
                nextgcore_sbcap_gen::decode(&pdu).unwrap(),
                nextgcore_sbcap_gen::generated::SBC_AP_PDU::SuccessfulOutcome(_)
            ));
            server.stop();
        }

        /// #1071 stage 3, TS 29.168 §4.3.3E / TS 23.007 §15A.1.2: an eNB's accepted
        /// PWS RESTART INDICATION reaches the associated CBC as SBc-AP
        /// PWS-Restart-Indication on PPID 24. With the server stopped (SBc-AP not
        /// configured) it is counted as unsent.
        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn an_enb_restart_reaches_the_cbc() {
            let _guard = SERVER_TEST_LOCK.lock().await;
            let ctx = static_ctx();
            let plmn = [0x00, 0xf1, 0x10];
            let enb = ctx.enb_add("127.0.0.1:36412".parse().unwrap());
            ctx.enb_set_s1_connected_for_test(enb, &plmn, nextgcore_s1ap::EnbId::Macro(0x1071));
            let msg = crate::s1ap_gen::PwsRestartIndication {
                global_enb_id: nextgcore_s1ap::GlobalEnbId {
                    plmn_identity: plmn,
                    enb_id: nextgcore_s1ap::EnbId::Macro(0x1071),
                },
                ecgi_list: vec![nextgcore_s1ap::EutranCgi {
                    plmn_identity: plmn,
                    cell_identity: 0x0107_1001,
                }],
                tai_list: vec![nextgcore_s1ap::Tai {
                    plmn_identity: plmn,
                    tac: 1,
                }],
                emergency_area_ids: Vec::new(),
            };
            let mut server = SbcapServer::bind(config(&["127.0.0.1"], 4), ctx)
                .await
                .unwrap();
            let bound = server.local_addr().unwrap();
            let client = tokio::task::spawn_blocking(move || {
                nextgcore_sctp::KernelSctpSocket::client(bound, None).unwrap()
            })
            .await
            .unwrap();
            drive(&mut server, |s| s.num_associations() == 1).await;

            let sent_before = INDICATIONS_SENT_TOTAL.load(Ordering::Relaxed);
            assert!(crate::s1ap_handler::handle_pws_restart(ctx, enb, &msg));
            drive(&mut server, |_| {
                INDICATIONS_SENT_TOTAL.load(Ordering::Relaxed) > sent_before
            })
            .await;
            assert!(
                INDICATIONS_SENT_TOTAL.load(Ordering::Relaxed) > sent_before,
                "the indication went out on the CBC association"
            );
            let (pdu, ppid) = tokio::task::spawn_blocking(move || recv(&client))
                .await
                .unwrap()
                .expect("the indication");
            assert_eq!(ppid, SBCAP_PPID);
            assert_eq!(
                pdu,
                crate::sbcap_handler::pws_restart_indication(&msg).unwrap(),
                "the eNB's indication, relayed"
            );

            server.stop();
            let unsent_before = INDICATIONS_UNSENT_TOTAL.load(Ordering::Relaxed);
            assert!(crate::s1ap_handler::handle_pws_restart(ctx, enb, &msg));
            assert_eq!(
                INDICATIONS_UNSENT_TOTAL.load(Ordering::Relaxed),
                unsent_before + 1,
                "no SBc-AP: counted, not queued"
            );
        }

        /// A peer that is not a configured CBC gets an SCTP ABORT and is counted;
        /// so is one association past `max_associations`.
        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn others_are_aborted_and_counted() {
            let _guard = SERVER_TEST_LOCK.lock().await;
            // (allowed CBC, max_associations, clients, the counter of the refusal)
            for (cbc, max, n, counter) in [
                ("127.0.0.2", 4, 1, &REFUSED_PEER_TOTAL),
                ("127.0.0.1", 1, 2, &REFUSED_LIMIT_TOTAL),
            ] {
                let mut server = SbcapServer::bind(config(&[cbc], max), static_ctx())
                    .await
                    .unwrap();
                let bound = server.local_addr().unwrap();
                let before = counter.load(Ordering::Relaxed);
                let mut clients = Vec::new();
                for _ in 0..n {
                    clients.push(
                        tokio::task::spawn_blocking(move || {
                            nextgcore_sctp::KernelSctpSocket::client(bound, None).unwrap()
                        })
                        .await
                        .unwrap(),
                    );
                    drive(&mut server, |_| false).await;
                }
                assert_eq!(counter.load(Ordering::Relaxed), before + 1, "{cbc}");
                let refused = clients.pop().unwrap();
                let got = tokio::task::spawn_blocking(move || recv(&refused))
                    .await
                    .unwrap();
                assert!(got.is_none(), "the refused association is gone ({cbc})");
                assert_eq!(server.num_associations(), clients.len());
                server.stop();
            }
        }
    }
}
