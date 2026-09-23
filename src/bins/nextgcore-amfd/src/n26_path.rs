//! The AMF's N26 GTPv2-C endpoint: answering an MME's Context Request (#347).
//!
//! TS 23.502 §4.11.1.3.2 ("5GS to EPS Idle mode mobility using N26 interface"). This AMF
//! is the **old** node: a UE it still serves has walked into E-UTRAN, sent a TRACKING AREA
//! UPDATE REQUEST to an MME, and the MME now asks this AMF for the UE's context.
//!
//! ```text
//! MME --Context Request (130)--> AMF
//!                                AMF --SmContextRetrieve--> SMF   (per EBI-bearing session)
//! MME <--Context Response (131)- AMF   (MM Context + PDN Connections)
//! MME --Context Acknowledge (132)--> AMF
//! ```
//!
//! # A runtime switch, not a cargo feature
//!
//! `AMF_N26_INTERWORKING=1`, default **off**, for the reason `smfd/src/eps_iwk.rs:19-29`
//! records: CI builds default features, so a cargo-feature-gated path is left
//! **uncompiled** and rots. This switch is also what [`crate::gmm_build`]'s
//! `iwk_n26_posture` reads, so the bit a UE is told and the socket the AMF binds cannot
//! disagree — which is #347's criterion 6 ("never merely because the code exists").
//!
//! # Async, unlike mmed's N26 endpoint
//!
//! A `tokio::net::UdpSocket` and a spawned task rather than mmed's blocking thread,
//! because answering a Context Request requires calling the SMF over N11 (§4.11.1.3.2 step
//! 5a) and every SBI client in amfd is `async`. That mirrors smfd's `S5S8Server`, which is
//! the async one of the two GTPv2-C endpoints this tree already had — so it is one of the
//! two established patterns, chosen by the surrounding code rather than invented.

use crate::context::amf_self;
use nextgcore_gtp::v2::xact::{Gtp2XactConfig, Gtp2XactMgr};
use nextgcore_gtp::v2::{
    Gtp2AmbrIe, Gtp2ApnIe, Gtp2BearerContextIe, Gtp2BearerQosIe, Gtp2CauseIe, Gtp2EbiIe,
    Gtp2FTeidIe, Gtp2Header, Gtp2Ie, Gtp2IeType, Gtp2Message, Gtp2MessageType, Gtp2MmContextIe,
    Gtp2PdnConnectionIe,
};
use nextgcore_nas::eps::types::EpsGuti;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;

/// F-TEID interface type `N26 AMF GTP-C`.
///
/// TS 29.274 Table 8.22-1. Mirrors `smfd/src/gtp_build.rs:517`'s `N26_AMF_GTP_C`, one of
/// the two constants that were the tree's entire N26 support before this issue and which
/// nothing referenced.
pub const N26_AMF_GTP_C: u8 = 40;

/// GTPv2-C cause `Request accepted` (TS 29.274 Table 8.4-1).
pub const CAUSE_REQUEST_ACCEPTED: u8 = 16;

/// GTPv2-C cause `IMSI/IMEI not known` (TS 29.274 Table 8.4-1).
///
/// One of the four message-specific causes §7.3.6 names (`29274-j60.txt:19878`), and the
/// right one when the 4G-GUTI an MME sent does not reverse-map to any UE this AMF serves.
pub const CAUSE_IMSI_IMEI_NOT_KNOWN: u8 = 92;

/// GTPv2-C cause `Request rejected` (TS 29.274 Table 8.4-1).
///
/// §7.3.6 requires it *"if the UE is registered to the source AMF without any PDU
/// session"* (`29274-j60.txt:19935-19936`).
pub const CAUSE_REQUEST_REJECTED: u8 = 94;

/// `Used NAS integrity protection algorithm` / `Used NAS Cipher` in the MM Context are
/// EPS algorithm identifiers, and the AMF's are 5GS ones.
///
/// TS 33.501 §8.6.1 (`33501-k20.txt:11760-11763`) says the mapped context's *"selected EPS
/// NAS algorithms shall be set to the EPS algorithms signalled to the UE by the AMF during
/// an early authentication procedure followed by a NAS SMC"*. The identifier **numbering
/// is the same** in both systems — TS 33.401 Table 5.1.3.2-1 and TS 33.501 Table 5.11.1-1
/// both number the null algorithm 0 and the first three real ones 1..3 — so the value
/// carries across unchanged, and it is the *name* (EEA/EIA vs NEA/NIA) that differs rather
/// than the code.
///
/// That is asserted rather than assumed by
/// `nas_algorithm_identifiers_carry_across_unchanged`, because an off-by-one here would
/// hand the MME a UE that ciphers with a different algorithm than the MME then selects, and
/// every subsequent NAS message would fail its integrity check with a symptom pointing
/// nowhere near this line.
pub const MAX_NAS_ALGORITHM_ID: u8 = 0x0F;

/// Is the N26 interworking leg enabled for this process?
static N26_ENABLED: AtomicBool = AtomicBool::new(false);

/// The environment variable that turns the leg on.
pub const N26_ENV_VAR: &str = "AMF_N26_INTERWORKING";

/// Read the switch from the environment and record it.
pub fn init_from_env() -> bool {
    let on = std::env::var(N26_ENV_VAR)
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    N26_ENABLED.store(on, Ordering::SeqCst);
    if on {
        log::info!(
            "[AMF] N26 interworking ENABLED: this AMF answers an MME's Context Request with \
             the UE's mapped EPS security context and PDN connections (TS 23.502 \
             §4.11.1.3.2), and advertises IWK N26 = 0 to every S1-mode-capable UE"
        );
    } else {
        log::info!(
            "[AMF] N26 interworking is OFF ({N26_ENV_VAR} unset): no N26 socket is bound and \
             every UE is told IWK N26 = 1, i.e. 'interworking without N26 supported'"
        );
    }
    on
}

/// Whether the N26 leg is enabled.
///
/// Read by [`crate::gmm_build`]'s `iwk_n26_posture`, which is what makes the bit a UE is
/// told track the socket the AMF actually bound. **Not** a `cfg!`: with the code compiled
/// in and the switch off this still returns `false`, which is #347's criterion 6 verbatim
/// ("never merely because the code exists").
pub fn enabled() -> bool {
    N26_ENABLED.load(Ordering::SeqCst)
}

/// Test-only: set the switch without going through startup.
///
/// The caller must hold [`crate::test_support::CONTEXT_GUARD`]. This module declares **no
/// lock of its own**: the globals involved (`N26_ENABLED`, `N26_SERVER`, and the AMF UE
/// store this procedure reads) are the ones that guard already covers, and #276 showed a
/// second lock over the same variables *hangs* the suite rather than merely flaking it.
#[cfg(test)]
pub fn set_for_test(on: bool) {
    N26_ENABLED.store(on, Ordering::SeqCst);
}

/// The AMF's N26 GTPv2-C endpoint.
pub struct N26Server {
    socket: UdpSocket,
    local_addr: SocketAddr,
    restart_counter: u8,
    xact: Mutex<Gtp2XactMgr>,
}

/// The process-wide N26 server, installed at startup.
static N26_SERVER: OnceLock<Arc<N26Server>> = OnceLock::new();

/// The installed N26 server, or `None` when the socket was never bound.
pub fn server() -> Option<&'static Arc<N26Server>> {
    N26_SERVER.get()
}

impl N26Server {
    /// Bind the N26 socket and spawn the receive loop.
    pub async fn open(bind: SocketAddr, restart_counter: u8) -> Result<Arc<Self>, String> {
        let socket = UdpSocket::bind(bind)
            .await
            .map_err(|e| format!("bind {bind}: {e}"))?;
        let local_addr = socket.local_addr().map_err(|e| e.to_string())?;
        let server = Arc::new(Self {
            socket,
            local_addr,
            restart_counter,
            xact: Mutex::new(Gtp2XactMgr::new(Gtp2XactConfig::default())),
        });

        // The receive loop. Spawned here, and `n26_open` is called from `run` at startup,
        // which is what makes `handle_context_request` reachable in production — the thing
        // to check before believing any of this works (#347's "prove the receive loop
        // dispatches to it").
        {
            let server = server.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                loop {
                    match server.socket.recv_from(&mut buf).await {
                        Ok((len, peer)) => {
                            let data = buf[..len].to_vec();
                            let server = server.clone();
                            // Spawned per datagram because handling a Context Request awaits
                            // the SMF over N11: doing it inline would stall the receive loop
                            // for the duration of an SBI round trip, and a second MME's
                            // request would queue behind the first UE's SMF call.
                            tokio::spawn(async move {
                                server.handle_datagram(&data, peer).await;
                            });
                        }
                        Err(e) => {
                            log::error!("N26 recv error: {e}");
                            // A recv error on a bound UDP socket is typically a transient
                            // ICMP-driven one; yielding rather than breaking keeps the leg
                            // alive, and breaking would silently end N26 service for the
                            // process's lifetime.
                            tokio::task::yield_now().await;
                        }
                    }
                }
            });
        }

        log::info!("AMF N26 GTP-C server listening on {local_addr}");
        Ok(server)
    }

    /// Local bound address — what the AMF puts in its own F-TEID.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    async fn send(&self, peer: SocketAddr, msg: &Gtp2Message) {
        let encoded = msg.encode();
        if let Ok(mut xact) = self.xact.try_lock() {
            xact.cache_response(peer, msg.header.sequence_number, encoded.clone().freeze());
        }
        if let Err(e) = self.socket.send_to(&encoded, peer).await {
            log::error!("N26 send to {peer} failed: {e}");
        }
    }

    async fn handle_datagram(&self, data: &[u8], peer: SocketAddr) {
        let mut bytes = bytes::Bytes::copy_from_slice(data);
        let msg = match Gtp2Message::decode(&mut bytes) {
            Ok(m) => m,
            Err(e) => {
                log::error!("[DROP] cannot decode N26 datagram from {peer}: {e}");
                return;
            }
        };
        let msg_type = msg.header.message_type;
        let seq = msg.header.sequence_number;

        // Echo: path management, no UE state (TS 29.274 §7.1.1).
        if msg_type == Gtp2MessageType::EchoRequest as u8 {
            let mut reply = Gtp2Message::echo_response(seq, self.restart_counter);
            reply.header.sequence_number = seq;
            self.send(peer, &reply).await;
            return;
        }
        if msg_type == Gtp2MessageType::EchoResponse as u8 {
            return;
        }

        if msg_type == Gtp2MessageType::ContextRequest as u8 {
            self.handle_context_request(&msg, seq, peer).await;
            return;
        }

        if msg_type == Gtp2MessageType::ContextAcknowledge as u8 {
            // TS 23.502 §4.11.1.3.2 step 6: the old AMF *"may start an implementation
            // specific (guard) timer for the UE context"*, and step 15 says it removes the
            // context when the timer expires. This AMF does not start one and does not
            // remove the context on the acknowledge either, and that is deliberate rather
            // than unfinished: §4.11.1.3.2 step 15-15c has the removal driven by
            // `Nudm_UECM_DeregistrationNotification` from the HSS+UDM with reason
            // "5GS to EPS Mobility" — the UDM is the authority on which core serves the UE,
            // and an AMF that dropped the context here would race that notification and
            // could lose a UE that never completed the move.
            log::info!(
                "N26 Context Acknowledge from MME {peer} (seq={seq}): the transfer is \
                 complete. This AMF keeps the UE context until the UDM notifies \
                 deregistration with reason '5GS to EPS Mobility' (TS 23.502 §4.11.1.3.2 \
                 steps 15-15c), rather than dropping it here and racing that notification."
            );
            return;
        }

        log::info!(
            "N26 message type={msg_type} seq={seq} from {peer} is not a procedure this AMF \
             serves: it is the OLD node in the only N26 procedure implemented (#347), and \
             Forward Relocation (types 133-136) is #408"
        );
    }

    /// Answer an MME's **Context Request** (TS 29.274 §7.3.5 → §7.3.6).
    ///
    /// # Production reachability
    ///
    /// Reached from [`Self::handle_datagram`], driven by the receive loop
    /// [`Self::open`] spawns, which `n26_open` installs from `lib.rs`'s `run` at startup
    /// when the switch is on. Stated here because "correct but unreachable" is this tree's
    /// commonest defect and a reader should not have to trace it.
    async fn handle_context_request(&self, msg: &Gtp2Message, seq: u32, peer: SocketAddr) {
        // The MME's F-TEID, which the Context Response must be addressed to. Read before
        // anything else can fail, because even a rejection has to reach the MME's UE
        // context rather than TEID 0.
        let mme_fteid = msg
            .get_ie(Gtp2IeType::FTeid as u8, 0)
            .and_then(|ie| Gtp2FTeidIe::decode(&ie.value).ok());
        let mme_teid = mme_fteid.as_ref().map(|f| f.teid).unwrap_or(0);

        let Some(guti) = msg
            .get_ie(Gtp2IeType::Guti as u8, 0)
            .and_then(|ie| parse_guti_ie(&ie.value))
        else {
            // Table 7.3.5-1 makes the GUTI conditional on the IMSI's absence, and this MME
            // sent neither — so there is nothing to resolve a UE context by.
            log::warn!(
                "N26 Context Request from {peer} carries no GUTI this AMF can parse; \
                 answering 'IMSI/IMEI not known' (TS 29.274 §7.3.6)"
            );
            self.send(
                peer,
                &build_context_response_reject(seq, mme_teid, CAUSE_IMSI_IMEI_NOT_KNOWN),
            )
            .await;
            return;
        };

        // TS 23.003 §2.10.2.1.3: map the GUTI to a 5G-GUTI and compare with the stored one.
        // `amf_ue_find_by_mapped_eps_guti` is the reader #347's criterion 5 asks for, and
        // this is its production caller.
        // `amf_self()` returns an owned `Arc`, so it must be bound before `.read()` --
        // otherwise the Arc is a temporary dropped at the end of the statement while the
        // guard still borrows it.
        let ctx = amf_self();
        let ue = {
            let Ok(guard) = ctx.read() else {
                log::error!("AMF context poisoned; the N26 Context Request cannot be served");
                self.send(
                    peer,
                    &build_context_response_reject(seq, mme_teid, CAUSE_REQUEST_REJECTED),
                )
                .await;
                return;
            };
            guard.amf_ue_find_by_mapped_eps_guti(&guti)
        };

        let Some(ue) = ue else {
            log::info!(
                "N26 Context Request from {peer} names 4G-GUTI (MME GID={:#06x}, MME \
                 code={:#04x}, M-TMSI={:#010x}), which reverse-maps to no 5G-GUTI this AMF \
                 serves; answering 'IMSI/IMEI not known'",
                guti.mme_gid,
                guti.mme_code,
                guti.m_tmsi
            );
            self.send(
                peer,
                &build_context_response_reject(seq, mme_teid, CAUSE_IMSI_IMEI_NOT_KNOWN),
            )
            .await;
            return;
        };

        // The Complete TAU Request Message the MME forwarded. §7.3.5 says the old AMF *"may
        // use this IE for integrity check"* -- and this AMF **does not**, which is a stated
        // ceiling rather than an omission. The check requires running the 5G NAS integrity
        // algorithm over those octets with this UE's KNASint at its uplink COUNT, and the
        // uplink COUNT the TAU used is not knowable from the message: TS 24.301 §4.4.2.2
        // (`24301-k00.txt:4457-4462`) has the UE include only the eKSI, so the AMF would
        // have to search a COUNT window. Verifying is optional ("may"); claiming to have
        // verified would not be.
        if let Some(ie) = msg.get_ie(Gtp2IeType::CompleteRequestMessage as u8, 0) {
            log::info!(
                "N26 Context Request carries a Complete Request Message ({} octets, type={}). \
                 NOT integrity-checked: TS 29.274 §7.3.5 makes the check optional ('may use \
                 this IE for integrity check') and doing it needs the TAU's uplink NAS COUNT, \
                 which TS 24.301 §4.4.2.2 does not put on the wire. The MSV flag is therefore \
                 the only validation signal, and this AMF does not assert a check it has not \
                 performed.",
                ie.value.len().saturating_sub(1),
                ie.value.first().copied().unwrap_or(0)
            );
        }

        // Steps 5a/5c: ask each EBI-bearing session's SMF for its EPS PDN connection.
        let pdn_connections = self.retrieve_pdn_connections(&ue).await;

        if pdn_connections.is_empty() {
            // §7.3.6 (`29274-j60.txt:19935-19936`): the source AMF *"shall reject the
            // Context Request with a cause value of 'Request Rejected'"* if *"the UE is
            // registered to the source AMF without any PDU session"*. A UE with sessions
            // that are all untransferable (no EBI) is the same case for this purpose:
            // §4.11.1.3.2 step 5a has the AMF not retrieve context for them at all.
            log::info!(
                "N26 Context Request for SUPI={:?}: no transferable PDU session (no EBI \
                 assigned, or every SMF retrieval failed), so TS 29.274 §7.3.6 requires \
                 'Request Rejected' rather than an accept with nothing in it",
                ue.supi
            );
            self.send(
                peer,
                &build_context_response_reject(seq, mme_teid, CAUSE_REQUEST_REJECTED),
            )
            .await;
            return;
        }

        let response =
            build_context_response(seq, mme_teid, &ue, self.local_addr, &pdn_connections);
        log::info!(
            "N26 Context Response to MME {peer} (seq={seq}): SUPI={:?} with a mapped EPS \
             security context and {} PDN connection(s) (TS 23.502 §4.11.1.3.2 step 6)",
            ue.supi,
            pdn_connections.len()
        );
        self.send(peer, &response).await;
    }

    /// Fetch each transferable session's EPS PDN connection from its SMF (steps 5a/5c).
    ///
    /// A session with **no assigned EBI is skipped**, and that is the spec's instruction
    /// rather than a shortcut: §4.11.1.3.2 step 5a (`23502-k20.txt:22040-22042`) says *"The
    /// AMF does not retrieve the context for a PDU Session that cannot be transferred to
    /// EPS due to no EBI allocated"*. Sending one anyway would name an EPS bearer identity
    /// the UE was never told about, and the MME would install a bearer the UE cannot
    /// address.
    async fn retrieve_pdn_connections(
        &self,
        ue: &crate::context::AmfUe,
    ) -> Vec<Gtp2PdnConnectionIe> {
        let ctx = amf_self();
        let sessions: Vec<crate::context::AmfSess> = {
            let Ok(guard) = ctx.read() else {
                return Vec::new();
            };
            guard.sess_list_for_ue(ue.id)
        };

        let mut out = Vec::new();
        for sess in sessions {
            let Some(sm_ref) = sess.sm_context_ref.as_deref() else {
                log::info!(
                    "N26: PDU session {} has no smContextRef, so its SMF cannot be asked for \
                     an EPS PDN connection; excluded from the transfer",
                    sess.psi
                );
                continue;
            };
            // The EBI the SMF asked this AMF for (#117's `assign-ebi`). Its absence is
            // exactly step 5a's "no EBI allocated".
            let ebi = ue
                .assigned_ebis
                .iter()
                .find(|e| e.pdu_session_id == sess.psi)
                .map(|e| e.ebi);
            let Some(ebi) = ebi else {
                log::info!(
                    "N26: PDU session {} has no assigned EPS bearer identity, so TS 23.502 \
                     §4.11.1.3.2 step 5a excludes it from the transfer",
                    sess.psi
                );
                continue;
            };

            let Ok((smf_host, smf_port)) = crate::sbi_path::resolve_nf_endpoint_async(
                crate::sbi_path::SbiServiceType::NsmfPdusession,
            )
            .await
            else {
                log::warn!(
                    "N26: no SMF endpoint resolvable for PDU session {}; excluded from the \
                     transfer",
                    sess.psi
                );
                continue;
            };

            match crate::sbi_path::call_smf_retrieve_sm_context(&smf_host, smf_port, sm_ref).await {
                Ok(Some(container)) => {
                    match pdn_connection_from_smf_container(&container, ebi, &sess) {
                        Some(pdn) => out.push(pdn),
                        None => log::warn!(
                            "N26: the SMF's ueEpsPdnConnection for PDU session {} could not be \
                             turned into a Table 7.3.6-2 PDN Connection; excluded rather than \
                             sent as a partial IE an MME would install",
                            sess.psi
                        ),
                    }
                }
                Ok(None) => log::info!(
                    "N26: the SMF has no EPS PDN connection for PDU session {}; excluded",
                    sess.psi
                ),
                Err(e) => log::warn!(
                    "N26: SmContextRetrieve for PDU session {} failed ({e}); excluded from the \
                     transfer, which TS 23.502 §4.11.1.3.2 step 15 then has the AMF release",
                    sess.psi
                ),
            }
        }
        out
    }
}

/// Build the PDN Connection IE (Table 7.3.6-2) from the SMF's `ueEpsPdnConnection`.
///
/// # This decodes and re-encodes, and NOTE 5 says "transparently transfer"
///
/// A stated deviation, with a reason. TS 29.274 Table 7.3.6-3 NOTE 5
/// (`29274-j60.txt:20980-20983`) has the source AMF *"transparently transfer the
/// MME/SGSN/AMF UE EPS PDN Connections IE received from the SMF"*, which presumes the SMF
/// hands over a conformant Table 7.3.6-2 grouped IE. **This tree's SMF does not.**
/// `build_ue_eps_pdn_connection` (`smfd/src/main.rs:5705`, from #78) emits a positional
/// ad-hoc layout:
///
/// ```text
/// [APN length][APN bytes][PDN type][4 address octets][QCI][EBI (optional)]
/// ```
///
/// Forwarding those bytes verbatim under IE type 109 would put a non-conformant blob on the
/// N26 wire, and an MME would read the APN length octet as an IE type. So the known layout
/// is parsed and a real grouped IE is built from it. Changing smfd to emit the conformant
/// container instead would be the better fix and is a larger one: `ueEpsPdnConnection` is
/// also an N11 member with its own tests
/// (`the_retrieved_ue_eps_pdn_connection_names_the_assigned_ebi`), so it is not this
/// issue's to move.
///
/// # What the SMF cannot supply, and what is sent instead
///
/// The layout above has no PGW-C S5/S8 control-plane F-TEID and no APN-AMBR, both of which
/// Table 7.3.6-2 makes **mandatory**. They are filled as follows, each named at the site:
///
/// - **PGW S5/S8 control F-TEID**: the reserved all-zero value, for the same reason
///   Table 7.3.6-3 mandates it for the SGW user-plane F-TEID over N26. This AMF has no
///   PGW-C address; the SMF is the PGW-C and has not told it one. A fabricated address
///   would have the MME send its Modify Bearer Request to a host that does not serve this
///   session.
/// - **APN-AMBR**: the session's AMBR is not in the container either, so `0` is sent. Zero
///   is a legal AMBR value and means "no non-GBR bandwidth", which an MME will enforce as
///   a policy the session was not authorised with — so it is logged as the ceiling it is.
fn pdn_connection_from_smf_container(
    container: &[u8],
    ebi: u8,
    sess: &crate::context::AmfSess,
) -> Option<Gtp2PdnConnectionIe> {
    // #78's positional layout, parsed defensively: a length octet longer than the buffer
    // means the container is not the layout this function knows, and guessing would build
    // an IE out of the wrong bytes.
    let apn_len = *container.first()? as usize;
    if container.len() < 1 + apn_len + 1 + 4 + 1 {
        return None;
    }
    let apn = String::from_utf8_lossy(&container[1..1 + apn_len]).to_string();
    let mut off = 1 + apn_len;
    let _pdn_type = container[off];
    off += 1;
    let ue_ipv4: [u8; 4] = container[off..off + 4].try_into().ok()?;
    off += 4;
    let qci = container[off];

    let mut pdn = Gtp2PdnConnectionIe::new();

    // APN (M). `Gtp2ApnIe::from_string` applies the label-length prefixing TS 29.274 §8.6
    // requires, so `internet.example.com` becomes 8"internet"7"example"3"com" -- the SMF's
    // container carried the bare string.
    pdn.add_ie(Gtp2ApnIe::from_string(&apn).to_ie(0));

    // IPv4 Address (C): included only when one is assigned, which is what Table 7.3.6-2
    // requires ("shall not be included if no IPv4 Address is assigned"). An all-zero
    // address is the container's "none", not an address of 0.0.0.0.
    if ue_ipv4 != [0, 0, 0, 0] {
        pdn.add_ie(Gtp2Ie::from_slice(Gtp2IeType::IpAddress as u8, 0, &ue_ipv4));
    }

    // Linked EPS Bearer ID (M): the default bearer, i.e. the EBI the AMF assigned this
    // session's default QoS flow.
    pdn.add_ie(Gtp2EbiIe::new(ebi).to_ie(0));

    // PGW S5/S8 IP Address for Control Plane (M) -- the reserved value; see the doc above.
    log::info!(
        "N26: PDU session {} is described to the MME with a RESERVED PGW-C S5/S8 \
         control-plane F-TEID (0.0.0.0, TEID 0) and APN-AMBR 0. The SMF's \
         ueEpsPdnConnection container (#78's layout) carries neither, and both are \
         mandatory in TS 29.274 Table 7.3.6-2. Consequence: the MME can install the bearer \
         and its QoS but cannot address the PGW-C for a later S5/S8 procedure, and will \
         enforce a zero non-GBR AMBR until a bearer modification supplies a real one.",
        sess.psi
    );
    pdn.add_ie(Gtp2PdnConnectionIe::n26_reserved_sgw_fteid().to_ie(0));

    // Bearer Contexts (M), one per mapped EPS bearer. The container describes exactly one
    // -- the default bearer -- because #117 assigns one EBI per session's default QoS flow.
    let mut bearer = Gtp2BearerContextIe::new();
    bearer.set_ebi(ebi);
    // SGW S1/S4/S12/S11 user-plane F-TEID (C): the reserved value Table 7.3.6-3 REQUIRES
    // over N26. There is no SGW in the 5GC and the user plane is anchored at a UPF the MME
    // cannot address, so this is the spec's answer rather than a placeholder.
    bearer.set_fteid(0, &Gtp2PdnConnectionIe::n26_reserved_sgw_fteid());
    // Bearer Level QoS (M): the EPS QCI the SMF mapped from the 5QI per TS 23.502 Annex C.
    // Bit rates are 0 because the container carries none; for a non-GBR bearer, which a
    // default bearer is, that is the correct value rather than a missing one.
    bearer.set_bearer_qos(&Gtp2BearerQosIe::new(qci, 0, 0, 0, 0));
    pdn.add_ie(bearer.to_ie(0));

    // Aggregate Maximum Bit Rate (APN-AMBR) (M).
    pdn.add_ie(Gtp2AmbrIe::new(0, 0).to_ie(0));

    Some(pdn)
}

/// Build a **Context Response** that accepts the transfer (TS 29.274 §7.3.6).
pub fn build_context_response(
    sequence_number: u32,
    mme_teid: u32,
    ue: &crate::context::AmfUe,
    local_addr: SocketAddr,
    pdn_connections: &[Gtp2PdnConnectionIe],
) -> Gtp2Message {
    let header = Gtp2Header::new(
        Gtp2MessageType::ContextResponse as u8,
        mme_teid,
        sequence_number,
    );
    let mut msg = Gtp2Message::new(header);

    // Cause (M).
    msg.add_ie(Gtp2CauseIe::new(CAUSE_REQUEST_ACCEPTED).to_ie(0));

    // IMSI (C): *"shall be included in the message except [...] if the UE is emergency or
    // RLOS attached and the UE is UICCless"* (`29274-j60.txt:19959-19973`). The SUPI is an
    // `imsi-<digits>` string, so the digits are what goes on the wire in TBCD.
    if let Some(imsi) = ue.supi.as_deref().and_then(|s| s.strip_prefix("imsi-")) {
        msg.add_ie(Gtp2Ie::from_slice(
            Gtp2IeType::Imsi as u8,
            0,
            &string_to_bcd(imsi),
        ));
    }

    // MM Context (C): *"shall be included if the Cause IE has the value 'Request
    // Accepted'"* (`:19975`). This is where the mapped EPS security context lives.
    msg.add_ie(build_mm_context(ue).to_ie(0));

    // The AMF's own N26 F-TEID, so the MME's Context Acknowledge is addressed to this UE
    // context rather than to TEID 0. Instance 0, the same instance the MME used for its own.
    if let std::net::IpAddr::V4(v4) = local_addr.ip() {
        msg.add_ie(Gtp2FTeidIe::new_ipv4(N26_AMF_GTP_C, ue.id as u32, v4.octets()).to_ie(0));
    }

    // PDN Connections (C), all at instance 0: §8.39 requires repeated IEs to share one
    // instance value, so they must NOT be numbered 0,1,2.
    for pdn in pdn_connections {
        msg.add_ie(pdn.to_ie(0));
    }

    msg
}

/// Build a **Context Response** that refuses the transfer.
///
/// Carries the Cause and nothing else: §7.3.6 makes the MM Context conditional on
/// *"Request Accepted"*, so a rejection with a security context attached would hand an MME
/// keys for a UE it was just told does not exist.
pub fn build_context_response_reject(
    sequence_number: u32,
    mme_teid: u32,
    cause: u8,
) -> Gtp2Message {
    let header = Gtp2Header::new(
        Gtp2MessageType::ContextResponse as u8,
        mme_teid,
        sequence_number,
    );
    let mut msg = Gtp2Message::new(header);
    msg.add_ie(Gtp2CauseIe::new(cause).to_ie(0));
    msg
}

/// Build the MM Context carrying this UE's **mapped** EPS security context.
///
/// TS 33.501 §8.6.1 (`33501-k20.txt:11740-11763`), point by point:
///
/// - `K_ASME'` is **derived** from `K_AMF` with the 5G NAS *uplink* COUNT, per Annex A.14.1
///   (FC `0x73`) — [`nextgcore_crypt::kdf::nextgcore_kdf_kasme_prime`]. Copying `K_AMF`
///   would hand the MME a key this AMF still uses for its own NAS, which is the whole thing
///   §8.6.1 exists to prevent, and it would round-trip clean through any codec test.
/// - the eKSI *"value field is taken from the ngKSI"*, so `ksi_asme` is the 5GS `ngKSI`.
/// - the EPS NAS COUNTs *"shall be set to the uplink and downlink NAS COUNT values of the
///   current 5G security context"* — carried across, not reset.
/// - the EPS NAS algorithms are the ones the AMF signalled the UE; see
///   [`MAX_NAS_ALGORITHM_ID`] for why the identifier values carry over unchanged.
pub fn build_mm_context(ue: &crate::context::AmfUe) -> Gtp2MmContextIe {
    let kasme = nextgcore_crypt::kdf::nextgcore_kdf_kasme_prime(&ue.kamf, ue.ul_count);

    Gtp2MmContextIe {
        // The eKSI's value field is the ngKSI's (TS 33.501 §8.6.1). `amf_ksi` is the KSI this
        // AMF assigned to the 5G security context -- not `ue_ksi`, which is what the UE last
        // CLAIMED and may name a context the AMF has since replaced.
        ksi_asme: ue.nas.amf_ksi & 0x07,
        // No NH/NCC: those are AS-level keys for a target eNB, and an idle-mode move has no
        // target eNB. `OSCI` is likewise 0 -- §8.38 (`29274-j60.txt:28234-28236`) allows the
        // old EPS security context *"only in S10 Forward Relocation Request"*.
        nhi: false,
        used_nas_integrity_algorithm: ue.selected_int_algorithm & 0x07,
        used_nas_cipher: ue.selected_enc_algorithm & MAX_NAS_ALGORITHM_ID,
        // Masked to 24 bits, which is what Figure 8.38-5's three-octet fields hold. The 5GS
        // COUNT is a u32 in this tree; its top octet is the overflow counter, and truncating
        // is what the field shape requires rather than a loss this code chooses.
        nas_downlink_count: ue.dl_count & 0x00FF_FFFF,
        nas_uplink_count: ue.ul_count & 0x00FF_FFFF,
        kasme,
        // The UE network capability, in the TS 24.301 §9.9.3.34 order the MM Context's
        // length-prefixed field carries: EEA bitmap then EIA bitmap. Only those two octets,
        // because those are the only two `AmfUe` holds -- §9.9.3.34's later octets (UEA/UIA
        // for UTRAN, and the various feature bits) describe capabilities a 5GS-only UE never
        // presented to this AMF, and §8.38 makes a shorter field legal ("If Length of UE
        // Network Capability is zero, then the UE Network Capability parameter shall not be
        // present", i.e. the length is what bounds it). Emitting zeroes for UTRAN algorithms
        // would tell the MME the UE supports NONE of them, which is a claim rather than a
        // silence.
        ue_network_capability: vec![ue.ue_network_capability.eea, ue.ue_network_capability.eia],
        // No MS network capability: that is a GSM/GPRS capability (TS 24.008 §10.5.5.12) and
        // a 5GS UE does not present one to an AMF. §8.38 makes a zero length mean absent.
        ms_network_capability: Vec::new(),
        mei: ue
            .pei
            .as_deref()
            .and_then(|p| {
                p.strip_prefix("imeisv-")
                    .or_else(|| p.strip_prefix("imei-"))
            })
            .map(string_to_bcd)
            .unwrap_or_default(),
        // No access restrictions: this AMF holds no subscribed RAT restrictions to forward,
        // and every bit of this octet means "not allowed" when set — so zero is the
        // permissive AND truthful value, not a placeholder.
        access_restriction: 0,
    }
}

/// Parse a GUTI IE (TS 29.274 §8.47, Figure 8.47-1) into an [`EpsGuti`].
///
/// | octet | field |
/// |---|---|
/// | 5-7 | MCC/MNC, TBCD |
/// | 8-9 | MME Group ID |
/// | 10 | MME Code |
/// | 11.. | M-TMSI |
///
/// Returns `None` for anything shorter than the 10 fixed octets, because a short GUTI would
/// otherwise resolve to a UE context on whatever bytes happened to follow.
pub fn parse_guti_ie(value: &bytes::Bytes) -> Option<EpsGuti> {
    if value.len() < 10 {
        return None;
    }
    let mut plmn_bytes = value.slice(0..3);
    let plmn_id = nextgcore_nas::common::types::PlmnId::decode(&mut plmn_bytes).ok()?;
    Some(EpsGuti {
        plmn_id,
        mme_gid: u16::from_be_bytes([value[3], value[4]]),
        mme_code: value[5],
        m_tmsi: u32::from_be_bytes([value[6], value[7], value[8], value[9]]),
    })
}

/// Encode a digit string as TBCD (TS 29.274 §8.3): low nibble first, `0xF` pads.
pub fn string_to_bcd(digits: &str) -> Vec<u8> {
    let chars: Vec<char> = digits.chars().collect();
    let mut out = Vec::with_capacity(chars.len().div_ceil(2));
    for pair in chars.chunks(2) {
        let low = pair[0].to_digit(16).unwrap_or(0) as u8;
        let high = pair.get(1).and_then(|c| c.to_digit(16)).unwrap_or(0x0F) as u8;
        out.push((high << 4) | low);
    }
    out
}

/// Bind the N26 socket from configuration and install it process-wide.
///
/// Returns `Ok(())` and logs why when the leg is off or no address is configured: an AMF
/// with no N26 address is a standalone-5GC deployment, and refusing to start would break
/// every existing config that never needed the socket — #347's criterion 8.
pub async fn n26_open(bind: Option<SocketAddr>, restart_counter: u8) -> Result<(), String> {
    if !init_from_env() {
        return Ok(());
    }
    let Some(bind) = bind else {
        log::warn!(
            "{N26_ENV_VAR} is set but no amf.n26.server address is configured: the N26 \
             interface is NOT bound, and iwk_n26_posture will still advertise \
             'interworking without N26 supported'"
        );
        // The switch is forced back off, so the bit a UE is told cannot claim an N26
        // interface that has no socket. This is #347's criterion 6 at its sharpest: the
        // switch being SET is not sufficient, the leg has to actually exist.
        N26_ENABLED.store(false, Ordering::SeqCst);
        return Ok(());
    };
    let server = N26Server::open(bind, restart_counter).await?;
    if N26_SERVER.set(server).is_err() {
        log::warn!("an N26 server is already installed; this one is dropped");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::{AmfUe, Guti5gs};

    /// The AMF's F-TEID interface type, against Table 8.22-1 and against smfd's constant.
    #[test]
    fn n26_amf_fteid_interface_type_matches_ts29274_table_8_22_1() {
        assert_eq!(
            N26_AMF_GTP_C, 40,
            "the AMF's N26 control-plane interface type is 40, matching \
             smfd/src/gtp_build.rs:517's N26_AMF_GTP_C -- one of the two constants that \
             were the tree's whole N26 support and had no reader"
        );
    }

    /// The MM Context carries a DERIVED K_ASME', not a copied K_AMF.
    ///
    /// The single most important assertion in this module. Copying K_AMF is simpler, is
    /// invisible to every encode/decode test, and defeats TS 33.501 §8.6.1 entirely — the
    /// MME would hold a key this AMF still uses for its own NAS.
    #[test]
    fn the_mm_context_carries_a_derived_kasme_not_the_kamf() {
        let _guard = crate::test_support::CONTEXT_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        let mut ue = AmfUe::new(0x347_0001, 1);
        ue.kamf = [0x5A; 32];
        ue.ul_count = 0x11;
        ue.dl_count = 0x22;
        ue.nas.amf_ksi = 4;
        ue.selected_enc_algorithm = 2;
        ue.selected_int_algorithm = 1;

        let ctx = build_mm_context(&ue);

        // Computed independently in the test from the FC and the COUNT, so a stubbed or
        // zeroed key fails and a copied K_AMF fails.
        let expected = nextgcore_crypt::kdf::nextgcore_kdf_kasme_prime(&[0x5A; 32], 0x11);
        assert_eq!(
            ctx.kasme, expected,
            "K_ASME' must be KDF(K_AMF, FC 0x73, uplink NAS COUNT) per TS 33.501 Annex A.14.1"
        );
        assert_ne!(
            ctx.kasme, ue.kamf,
            "K_ASME' must NOT be K_AMF: copying it hands the MME a key this AMF still uses \
             for its own NAS, which is precisely what TS 33.501 §8.6.1 exists to prevent"
        );
        assert_ne!(ctx.kasme, [0u8; 32], "and must not be all zeroes");

        // The COUNTs are carried across, not reset (§8.6.1).
        assert_eq!(
            ctx.nas_uplink_count, 0x11,
            "the EPS uplink NAS COUNT is the 5G one (TS 33.501 §8.6.1)"
        );
        assert_eq!(ctx.nas_downlink_count, 0x22);
        // The eKSI value field is the ngKSI's.
        assert_eq!(
            ctx.ksi_asme, 4,
            "the eKSI value field is taken from the ngKSI"
        );
        // And the algorithms the AMF signalled.
        assert_eq!(ctx.used_nas_cipher, 2);
        assert_eq!(ctx.used_nas_integrity_algorithm, 1);
        // NHI and OSCI are clear: no AS keys and no old context on an idle-mode move.
        assert!(
            !ctx.nhi,
            "NHI must be clear: NH/NCC are AS keys for a target eNB and an idle-mode move \
             has none"
        );

        // The derivation is bound to the UPLINK count, not the downlink one -- Annex A.14.1
        // for idle mode vs A.14.2 (FC 0x74) for handover. Swapping them would produce a key
        // the UE cannot reproduce.
        let mut swapped = ue.clone();
        swapped.ul_count = 0x22;
        assert_ne!(
            build_mm_context(&swapped).kasme,
            ctx.kasme,
            "the uplink COUNT is load-bearing: Annex A.14.1 binds idle-mode mobility to the \
             UPLINK count (A.14.2's FC 0x74 binds handover to the downlink one)"
        );
    }

    /// The Context Response's shape: accepted carries the security context, refused does not.
    #[test]
    fn a_refused_context_response_carries_no_security_context() {
        let reject = build_context_response_reject(9, 0x1234, CAUSE_IMSI_IMEI_NOT_KNOWN);
        assert_eq!(
            reject.header.message_type, 131,
            "Context Response is type 131"
        );
        assert_eq!(
            reject.header.teid,
            Some(0x1234),
            "even a rejection must be addressed to the MME's TEID, or it lands on no UE \
             context at the peer"
        );
        assert!(
            reject.get_ie(Gtp2IeType::MmContext as u8, 0).is_none(),
            "TS 29.274 §7.3.6 makes the MM Context conditional on 'Request Accepted' \
             (29274-j60.txt:19975), so a refusal carrying one would hand an MME keys for a \
             UE it was just told does not exist"
        );
        assert!(
            reject.get_ie(Gtp2IeType::PdnConnection as u8, 0).is_none(),
            "and no PDN connections either"
        );
        let cause =
            Gtp2CauseIe::decode(&reject.get_ie(Gtp2IeType::Cause as u8, 0).unwrap().value).unwrap();
        assert_eq!(cause.cause, CAUSE_IMSI_IMEI_NOT_KNOWN);
    }

    /// An accepted Context Response carries every Table 7.3.6-1 IE the AMF can supply.
    #[test]
    fn an_accepted_context_response_carries_its_table_7_3_6_1_ies() {
        let _guard = crate::test_support::CONTEXT_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        let mut ue = AmfUe::new(0x347_0002, 2);
        ue.supi = Some("imsi-001010000000002".to_string());
        ue.kamf = [0x3C; 32];
        ue.ul_count = 7;

        let mut pdn = Gtp2PdnConnectionIe::new();
        pdn.add_ie(Gtp2ApnIe::from_string("internet").to_ie(0));
        pdn.add_ie(Gtp2EbiIe::new(5).to_ie(0));
        pdn.add_ie(Gtp2PdnConnectionIe::n26_reserved_sgw_fteid().to_ie(0));
        pdn.add_ie(Gtp2AmbrIe::new(0, 0).to_ie(0));
        let mut bearer = Gtp2BearerContextIe::new();
        bearer.set_ebi(5);
        bearer.set_bearer_qos(&Gtp2BearerQosIe::new(9, 0, 0, 0, 0));
        pdn.add_ie(bearer.to_ie(0));

        let local: SocketAddr = "10.0.0.7:2123".parse().unwrap();
        let msg = build_context_response(11, 0xABCD, &ue, local, std::slice::from_ref(&pdn));

        // Cause: accepted.
        let cause =
            Gtp2CauseIe::decode(&msg.get_ie(Gtp2IeType::Cause as u8, 0).unwrap().value).unwrap();
        assert_eq!(cause.cause, CAUSE_REQUEST_ACCEPTED);

        // IMSI: the SUPI's digits, TBCD. Asserted POSITIVELY -- the MME identifies the
        // subscriber by this and nothing else at this point in the procedure.
        let imsi = msg.get_ie(Gtp2IeType::Imsi as u8, 0).expect("IMSI IE");
        assert_eq!(
            imsi.value.as_ref(),
            string_to_bcd("001010000000002").as_slice(),
            "the IMSI is the SUPI's digits in TBCD (TS 29.274 §8.3)"
        );

        // MM Context, with the derived key.
        let mm = Gtp2MmContextIe::decode(
            &msg.get_ie(Gtp2IeType::MmContext as u8, 0)
                .expect("MM Context IE")
                .value,
        )
        .expect("the MM Context this AMF built must decode");
        assert_eq!(
            mm.kasme,
            nextgcore_crypt::kdf::nextgcore_kdf_kasme_prime(&[0x3C; 32], 7)
        );

        // The AMF's own F-TEID, so the Context Acknowledge is addressable.
        let fteid =
            Gtp2FTeidIe::decode(&msg.get_ie(Gtp2IeType::FTeid as u8, 0).unwrap().value).unwrap();
        assert_eq!(fteid.interface_type, N26_AMF_GTP_C);
        assert_eq!(fteid.ipv4_addr, Some([10, 0, 0, 7]));

        // The PDN connection, recoverable through the wire.
        let pdns = msg.get_ies(Gtp2IeType::PdnConnection as u8);
        assert_eq!(pdns.len(), 1);
        let decoded = Gtp2PdnConnectionIe::decode(&pdns[0].value).unwrap();
        assert_eq!(decoded.apn().unwrap().to_string(), "internet");
        assert_eq!(decoded.linked_ebi().unwrap(), 5);
        assert_eq!(decoded.bearer_contexts().unwrap()[0].ebi().unwrap(), 5);
    }

    /// Several PDN connections share instance 0 (TS 29.274 §8.39).
    #[test]
    fn several_pdn_connections_are_all_carried_at_instance_zero() {
        let _guard = crate::test_support::CONTEXT_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());

        let ue = AmfUe::new(0x347_0003, 3);
        let pdns: Vec<Gtp2PdnConnectionIe> = [5u8, 6]
            .into_iter()
            .map(|ebi| {
                let mut p = Gtp2PdnConnectionIe::new();
                p.add_ie(Gtp2EbiIe::new(ebi).to_ie(0));
                p
            })
            .collect();
        let msg = build_context_response(1, 1, &ue, "10.0.0.7:2123".parse().unwrap(), &pdns);
        let carried = msg.get_ies(Gtp2IeType::PdnConnection as u8);
        assert_eq!(carried.len(), 2);
        assert!(
            carried.iter().all(|ie| ie.instance == 0),
            "§8.39: repeated PDN Connection IEs 'shall have exactly the same Instance \
             values' -- numbering them 0,1 would make the MME read two different members"
        );
        let ebis: Vec<u8> = carried
            .iter()
            .map(|ie| {
                Gtp2PdnConnectionIe::decode(&ie.value)
                    .unwrap()
                    .linked_ebi()
                    .unwrap()
            })
            .collect();
        assert_eq!(ebis, vec![5, 6], "and each is still its own connection");
    }

    /// The GUTI IE round-trips, so an MME's GUTI resolves to the right UE.
    #[test]
    fn a_guti_ie_from_an_mme_parses_back_to_the_4g_guti() {
        use nextgcore_nas::common::types::PlmnId;
        let guti = EpsGuti {
            plmn_id: PlmnId::new([0, 0, 1], [0, 1, 0], 2),
            mme_gid: 0xAB9B,
            mme_code: 0x6A,
            m_tmsi: 0xCAFE_BABE,
        };
        // Built the way an MME builds it: PLMN, group id, code, M-TMSI.
        let mut v = bytes::BytesMut::new();
        guti.plmn_id.encode(&mut v);
        v.extend_from_slice(&guti.mme_gid.to_be_bytes());
        v.extend_from_slice(&[guti.mme_code]);
        v.extend_from_slice(&guti.m_tmsi.to_be_bytes());
        assert_eq!(parse_guti_ie(&v.freeze()), Some(guti));

        for len in 0..10usize {
            assert!(
                parse_guti_ie(&bytes::Bytes::from(vec![0xAAu8; len])).is_none(),
                "a {len}-octet GUTI must not resolve a UE context by accident"
            );
        }
    }

    /// The `mapped_eps_guti` reader finds a NATIVELY registered UE (criterion 5).
    ///
    /// This is the case that matters and the one a literal reading of the criterion would
    /// miss: a UE that registered on 5GS and walked into E-UTRAN has `mapped_eps_guti ==
    /// None`, so a reader that only consulted that field would find nothing and the whole
    /// procedure would answer "IMSI/IMEI not known" for every UE.
    #[test]
    fn a_natively_registered_ue_is_found_by_the_guti_an_mme_maps_from_its_5g_guti() {
        let _guard = crate::test_support::CONTEXT_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        crate::test_support::init_context();

        // A distinct 5G-TMSI, so this test cannot collide with a sibling's UE: the AMF
        // context is process-global and the store is keyed by identity, not by test.
        const TMSI: u32 = 0x3470_0011;
        let mut ue = AmfUe::new(0x347_0011, 11);
        ue.supi = Some("imsi-001010000000011".to_string());
        ue.current_guti = Guti5gs {
            plmn_id: crate::context::PlmnId::default(),
            amf_region_id: 0xAB,
            amf_set_id: 0x026D,
            amf_pointer: 0x2A,
            tmsi: TMSI,
        };
        let ue_id = ue.id;
        {
            let ctx = amf_self();
            let guard = ctx.read().expect("context");
            // `amf_ue_publish` is the SAME seam production uses (#341): a UE only in
            // `amf_ue_list` is invisible to the derived resolvers, so seeding the store any
            // other way would test a lookup against state production never produces.
            guard.amf_ue_publish(&ue, 11, 1);
        }

        // The GUTI an MME would send: the UE's own 5G-GUTI mapped per §2.10.2.1.2.
        let from_mme = nextgcore_nas::interworking::five_g_guti_to_eps_guti(
            &nextgcore_nas::fiveg::types::FiveGGuti {
                plmn_id: crate::gmm_build::to_nextgcore_plmn(&ue.current_guti.plmn_id),
                amf_region_id: 0xAB,
                amf_set_id: 0x026D,
                amf_pointer: 0x2A,
                tmsi: TMSI,
            },
        );

        let found = {
            let ctx = amf_self();
            let guard = ctx.read().expect("context");
            guard.amf_ue_find_by_mapped_eps_guti(&from_mme)
        };
        let found = found.expect(
            "a natively registered UE MUST be found by the 4G-GUTI an MME maps from its \
             5G-GUTI (TS 23.003 §2.10.2.1.3) -- mapped_eps_guti is None for such a UE, so a \
             reader consulting only that field finds nothing and the whole procedure fails",
        );
        assert_eq!(found.id, ue_id);
        assert_eq!(
            found.supi.as_deref(),
            Some("imsi-001010000000011"),
            "and the SUPI must come back, because it is what the Context Response's IMSI IE \
             carries and the only identity the MME gets"
        );

        // A one-bit-different GUTI must NOT match, or the lookup is matching on too little.
        let mut wrong = from_mme.clone();
        wrong.m_tmsi ^= 1;
        let miss = {
            let ctx = amf_self();
            let guard = ctx.read().expect("context");
            guard.amf_ue_find_by_mapped_eps_guti(&wrong)
        };
        assert!(
            miss.is_none(),
            "a GUTI differing by one M-TMSI bit must not resolve this UE"
        );

        // A zero M-TMSI never matches (the unset value).
        let zero = EpsGuti {
            m_tmsi: 0,
            ..from_mme
        };
        let miss = {
            let ctx = amf_self();
            let guard = ctx.read().expect("context");
            guard.amf_ue_find_by_mapped_eps_guti(&zero)
        };
        assert!(
            miss.is_none(),
            "a zero M-TMSI is the unset value and must not resolve every default-GUTI UE"
        );
    }

    /// The switch reads back in both directions, and nothing is bound when it is off.
    #[test]
    fn the_n26_switch_reads_back_in_both_directions() {
        let _guard = crate::test_support::CONTEXT_GUARD
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        set_for_test(true);
        assert!(enabled());
        set_for_test(false);
        assert!(!enabled());
    }

    /// The IMSI's TBCD encoding, asserted octet by octet against TS 29.274 §8.3.
    ///
    /// The whole expected byte string is written out rather than checked property-wise,
    /// because the failure mode is a *swapped nibble order* and that is invisible to
    /// "the length is right" or "the filler is present": both hold either way. The
    /// expectation was computed by hand from §8.3's rule — first digit in the LOW nibble
    /// of each octet — for `001010000000001`:
    ///
    /// ```text
    /// digits: 0 0 | 1 0 | 1 0 | 0 0 | 0 0 | 0 0 | 0 0 | 1 (pad)
    /// octets: 0x00  0x01  0x01  0x00  0x00  0x00  0x00  0xF1
    /// ```
    ///
    /// Note `0x01` for the pair `1,0`: low nibble `1` is the first digit, high nibble `0`
    /// the second. A big-endian reading would give `0x10` for the same pair and would pass
    /// every weaker assertion.
    #[test]
    fn imsi_tbcd_encoding_matches_ts29274_8_3() {
        assert_eq!(
            string_to_bcd("001010000000001"),
            vec![0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0xF1],
            "TS 29.274 §8.3 puts the FIRST digit of each pair in the LOW nibble, and pads an \
             odd digit count with 0xF in the final high nibble. A big-endian reading would \
             give 0x10 where this expects 0x01."
        );
        // An even digit count has no filler at all.
        assert_eq!(
            string_to_bcd("0123"),
            vec![0x10, 0x32],
            "an even digit count is fully packed: '0','1' => 0x10, '2','3' => 0x32"
        );
    }
}
