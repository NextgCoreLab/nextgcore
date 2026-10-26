//! #607 (Create Bearer half): the Serving GW's part of dedicated bearer activation,
//! TS 23.401 §5.4.1 steps 2-3 and 7-8.
//!
//! Before this the SGW-C relayed the PGW's Create Bearer Request to the MME verbatim. The
//! MME was told the PGW's S5/S8-U F-TEID and no S1-U SGW F-TEID, so an eNB would have had
//! nowhere to send the bearer's uplink, and the SGW-U held no rule for the bearer in either
//! direction. An accepting Create Bearer Response was not relayed at all.
//!
//! **The procedure here.**
//! 1. Create Bearer Request from the PGW. For each Bearer Context the SGW-C:
//!    - stores a bearer with EBI 0, its QoS and the PGW's S5/S8-U F-TEID (Table 7.2.3-2,
//!      instance 1);
//!    - allocates its own S1-U and S5/S8-U F-TEIDs and rule ids, as Create Session does;
//!    - installs both directions at the SGW-U: the uplink PDR (Access, on the S1-U
//!      F-TEID) with a FAR to the PGW, and the downlink PDR (Core, on the S5/S8-U F-TEID)
//!      with a FAR that buffers until the eNB's F-TEID is known.
//! 2. When the SGW-U accepts, the request goes to the MME. Each Bearer Context gains the
//!    S1-U SGW F-TEID (instance 0) and keeps the PGW's S5/S8-U F-TEID (instance 1, "sent
//!    on the S11 interface for GTP-based S5/S8"). The Recovery IE is dropped: it is the
//!    PGW's restart counter, not this node's (TS 23.007 §18).
//! 3. The MME's Create Bearer Response (Table 7.2.4-2). For each accepted bearer the EBI
//!    and the S1-U eNodeB F-TEID (instance 0) are recorded and the downlink FAR forwards
//!    to the eNB; each refused one is removed at the SGW-U and here.
//! 4. When the SGW-U confirms, the PGW is answered under its sequence number with the
//!    S5/S8-U SGW F-TEID (instance 2) and the PGW's own (instance 3) of each bearer.
//!
//! A failure anywhere removes what was installed, and the PGW gets a refusal, so it rolls
//! the bearer back too:
//! - the SGW-U refuses: "System failure";
//! - the SGW-U or the MME never answers: "Remote peer not responding";
//! - the request lacks a mandatory or conditional IE: that IE's cause.
//!
//! **Known ceiling.** If the SGW-U refuses the downlink switch after the MME has accepted
//! (step 4), the PGW is told the bearer was not created while the MME holds it. That
//! needs the SGW-U to fail between two modifications it just accepted; it is logged.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use bytes::Bytes;
use nextgcore_gtp::v2::header::Gtp2MessageType;
use nextgcore_gtp::v2::{Gtp2BearerContextIe, Gtp2CauseIe, Gtp2FTeidIe, Gtp2IeType, Gtp2Message};

use crate::context::{sgwc_self, IpAddr as TunnelIp};
use crate::gtp_path::GtpcServer;
use crate::pfcp_path::{self, S11Continuation};
use crate::s11_build::{self, f_teid_interface};
use crate::s11_handler::gtp_cause;
use crate::sxa_handler::pfcp_modify;

/// One PGW Create Bearer Request this SGW-C is serving.
#[derive(Debug, Clone)]
struct PendingCreateBearer {
    /// The PGW that sent the request, its sequence number and its S5/S8-C TEID.
    pgw_peer: SocketAddr,
    pgw_seq: u32,
    pgw_teid: u32,
    sess_id: u64,
    /// The bearers created for the request's Bearer Contexts, in their order.
    bearer_ids: Vec<u64>,
    /// The PGW's request, which goes on to the MME once the SGW-U holds the rules.
    request: Gtp2Message,
    /// When a Command this node relayed triggered the request (#591): the MME it came
    /// from, the Command's S11 sequence number (which the request then carries) and the
    /// MME's S11 TEID.
    command: Option<(SocketAddr, u32, u32)>,
    /// The S11 leg, once the request is relayed: (MME, S11 sequence number).
    s11: Option<(SocketAddr, u32)>,
    /// The MME's answer: its message cause, and the outcome of each bearer.
    answer: Option<(u8, Vec<(u64, u8, u8)>)>,
}

/// The requests being served, by join id. A process-global, like `sgwc_self()`, whose
/// tests it shares the serialisation of (`pfcp_path::process_state_test_guard`).
static PENDING: Mutex<Option<HashMap<u64, PendingCreateBearer>>> = Mutex::new(None);
static NEXT_JOIN: AtomicU64 = AtomicU64::new(1);

fn with_pending<R>(f: impl FnOnce(&mut HashMap<u64, PendingCreateBearer>) -> R) -> R {
    let mut guard = PENDING.lock().unwrap_or_else(|e| e.into_inner());
    f(guard.get_or_insert_with(HashMap::new))
}

fn take(join: u64) -> Option<PendingCreateBearer> {
    with_pending(|p| p.remove(&join))
}

/// Whether the PGW's Create Bearer Request (`pgw_peer`, `pgw_seq`) is still being
/// served. A retransmission of it is then discarded (TS 29.274 §7.6): this node's own
/// legs retransmit on their own.
pub(crate) fn in_flight(pgw_peer: SocketAddr, pgw_seq: u32) -> bool {
    with_pending(|p| {
        p.values()
            .any(|r| r.pgw_peer == pgw_peer && r.pgw_seq == pgw_seq)
    }) || held()
        .iter()
        .any(|h| h.pgw_peer == pgw_peer && h.msg.header.sequence_number == pgw_seq)
}

/// A Create Bearer Request for a session whose Sxa establishment is still in
/// flight (#1283): it has no SGW-U SEID yet, so its rules cannot be installed.
/// A PGW activating a bearer at attach (TS 23.401 §5.4.1, Annex F) sends it
/// right after its Create Session Response, which can beat the SGW-U's answer.
struct Held {
    sess_id: u64,
    msg: Gtp2Message,
    pgw_peer: SocketAddr,
    command: Option<(SocketAddr, u32, u32)>,
    at: std::time::Instant,
}

static HELD: Mutex<Vec<Held>> = Mutex::new(Vec::new());

/// How long a held request may wait for its session's establishment: well
/// within the PGW's S5/S8 transaction.
const HOLD_MAX: std::time::Duration = std::time::Duration::from_secs(10);

fn held() -> std::sync::MutexGuard<'static, Vec<Held>> {
    HELD.lock().unwrap_or_else(|e| e.into_inner())
}

/// Session `sess_id`'s Sxa establishment succeeded: its held Create Bearer
/// Requests are carried out now (#1283).
pub(crate) fn on_session_established(sess_id: u64) {
    let ready: Vec<Held> = {
        let mut list = held();
        let (ready, kept): (Vec<_>, Vec<_>) = list.drain(..).partition(|h| h.sess_id == sess_id);
        *list = kept;
        ready
    };
    let Some(server) = server() else {
        return;
    };
    for h in ready {
        log::info!(
            "Create Bearer Request from PGW {} (seq {}): session {sess_id} is established; \
             carried out now",
            h.pgw_peer,
            h.msg.header.sequence_number
        );
        on_pgw_request(&server, &h.msg, h.pgw_peer, h.command);
    }
}

/// Session `sess_id` failed or went before its establishment completed: its
/// held Create Bearer Requests are refused "Context not found" (#1283).
pub(crate) fn on_session_failed(sess_id: u64) {
    let gone: Vec<Held> = {
        let mut list = held();
        let (gone, kept): (Vec<_>, Vec<_>) = list.drain(..).partition(|h| h.sess_id == sess_id);
        *list = kept;
        gone
    };
    refuse_held(gone);
}

fn refuse_held(gone: Vec<Held>) {
    let Some(server) = server() else {
        return;
    };
    let ctx = sgwc_self();
    for h in gone {
        let pgw_teid = ctx
            .sess_find_by_id(h.sess_id)
            .map(|s| s.pgw_s5c_teid)
            .unwrap_or(0);
        let cause = gtp_cause::CONTEXT_NOT_FOUND;
        answer_pgw(
            &server,
            h.pgw_peer,
            h.msg.header.sequence_number,
            pgw_teid,
            cause,
            &[(None, 0, cause)],
        );
        fail_command(&server, h.command, &h.msg, cause);
    }
}

/// Whether the S11 Create Bearer Response (`mme_peer`, `s11_seq`) answers a request this
/// module relayed.
pub(crate) fn owns_answer(mme_peer: SocketAddr, s11_seq: u32) -> bool {
    with_pending(|p| p.values().any(|r| r.s11 == Some((mme_peer, s11_seq))))
}

/// The number of requests being served (tests).
#[cfg(test)]
pub(crate) fn pending_count() -> usize {
    with_pending(|p| p.len())
}

/// A Bearer Context of the PGW's request, as far as this node needs it.
struct RequestedBearer {
    pgw_s5u: Gtp2FTeidIe,
    qos: nextgcore_gtp::v2::Gtp2BearerQosIe,
}

/// The Bearer Contexts (instance 0) of a Create Bearer Request, or the cause it is
/// refused with: TFT and Bearer QoS are mandatory (Table 7.2.3-2), and the S5/S8-U PGW
/// F-TEID is conditional on GTP-based S5/S8, which this is.
fn requested_bearers(msg: &Gtp2Message) -> Result<Vec<RequestedBearer>, u8> {
    let mut out = Vec::new();
    for ie in msg
        .get_ies(Gtp2IeType::BearerContext as u8)
        .into_iter()
        .filter(|ie| ie.instance == 0)
    {
        let bc = Gtp2BearerContextIe::decode(&Bytes::copy_from_slice(&ie.value))
            .map_err(|_| gtp_cause::MANDATORY_IE_INCORRECT)?;
        if bc.get_ie(Gtp2IeType::BearerTft as u8, 0).is_none() {
            return Err(gtp_cause::MANDATORY_IE_MISSING);
        }
        let qos = bc
            .bearer_qos()
            .ok()
            .flatten()
            .ok_or(gtp_cause::MANDATORY_IE_MISSING)?;
        let pgw_s5u = bc
            .fteid(1)
            .ok()
            .flatten()
            .filter(|f| f.ipv4_addr.is_some() || f.ipv6_addr.is_some())
            .ok_or(gtp_cause::CONDITIONAL_IE_MISSING)?;
        out.push(RequestedBearer { pgw_s5u, qos });
    }
    if out.is_empty() {
        return Err(gtp_cause::MANDATORY_IE_MISSING);
    }
    Ok(out)
}

/// A Create Bearer Response to the PGW (TS 29.274 §7.2.4, Table 7.2.4-2): `cause`, and
/// one Bearer Context per `(bearer, ebi, cause)`. An accepted bearer carries the S5/S8-U
/// SGW F-TEID (instance 2) and the PGW's (instance 3).
fn answer_pgw(
    server: &GtpcServer,
    pgw_peer: SocketAddr,
    pgw_seq: u32,
    pgw_teid: u32,
    cause: u8,
    bearers: &[(Option<u64>, u8, u8)],
) {
    let ctx = sgwc_self();
    let mut msg = Gtp2Message::new(nextgcore_gtp::v2::Gtp2Header::new(
        Gtp2MessageType::CreateBearerResponse as u8,
        pgw_teid,
        pgw_seq,
    ));
    msg.add_ie(Gtp2CauseIe::new(cause).to_ie(0));
    for &(bearer_id, ebi, bearer_cause) in bearers {
        let mut bc = Gtp2BearerContextIe::new();
        bc.set_ebi(ebi);
        bc.set_cause(&Gtp2CauseIe::new(bearer_cause));
        if bearer_cause == gtp_cause::REQUEST_ACCEPTED {
            if let Some(id) = bearer_id {
                if let Some(dl) = ctx.dl_tunnel_in_bearer(id) {
                    if let Ok(ft) = s11_build::fteid(
                        f_teid_interface::S5_S8_SGW_GTP_U,
                        dl.local_teid,
                        dl.local_addr,
                        dl.local_addr6,
                    ) {
                        bc.set_fteid(2, &ft);
                    }
                }
                if let Some(ul) = ctx.ul_tunnel_in_bearer(id) {
                    if let Ok(ft) = s11_build::fteid(
                        f_teid_interface::S5_S8_PGW_GTP_U,
                        ul.remote_teid,
                        ul.remote_ip.ipv4,
                        ul.remote_ip.ipv6,
                    ) {
                        bc.set_fteid(3, &ft);
                    }
                }
            }
        }
        msg.add_bearer_context(0, &bc);
    }
    log::info!(
        "Create Bearer Response to PGW {pgw_peer} (seq {pgw_seq}, S5-C TEID {pgw_teid:#x}): \
         cause {cause}, bearers {:?}",
        bearers
            .iter()
            .map(|&(_, ebi, c)| (ebi, c))
            .collect::<Vec<_>>()
    );
    if let Err(e) = server.send_response(pgw_peer, &msg) {
        log::error!("Create Bearer Response to PGW {pgw_peer} failed: {e}");
    }
}

/// Refuse the whole request: every Bearer Context gets EBI 0 and `cause`.
fn refuse(server: &GtpcServer, p: &PendingCreateBearer, cause: u8) {
    let bearers: Vec<(Option<u64>, u8, u8)> = p
        .bearer_ids
        .iter()
        .map(|&id| (Some(id), 0, cause))
        .collect();
    answer_pgw(server, p.pgw_peer, p.pgw_seq, p.pgw_teid, cause, &bearers);
    if p.s11.is_none() {
        fail_command(server, p.command, &p.request, cause);
    }
}

/// The MME's Bearer Resource Command whose triggered Create Bearer Request this node
/// refused before relaying it: answered with a Bearer Resource Failure Indication under
/// the Command's sequence number (TS 29.274 §7.2.6, Table 7.2.6-1: Cause, the Linked
/// EBI and the PTI), as a PGW's own refusal is relayed. Without it the MME's Command
/// would run out its N3 with no answer.
fn fail_command(
    server: &GtpcServer,
    command: Option<(SocketAddr, u32, u32)>,
    request: &Gtp2Message,
    cause: u8,
) {
    let Some((mme_peer, mme_seq, mme_teid)) = command else {
        return;
    };
    let mut bri = Gtp2Message::new(nextgcore_gtp::v2::Gtp2Header::new(
        Gtp2MessageType::BearerResourceFailureIndication as u8,
        mme_teid,
        mme_seq,
    ));
    bri.add_ie(Gtp2CauseIe::new(cause).to_ie(0));
    for ie_type in [Gtp2IeType::Ebi as u8, Gtp2IeType::Pti as u8] {
        if let Some(ie) = request.get_ie(ie_type, 0) {
            bri.add_ie(ie.clone());
        }
    }
    log::info!(
        "Bearer Resource Failure Indication to MME {mme_peer} (seq {mme_seq}): the triggered \
         Create Bearer Request was refused here, cause {cause}"
    );
    if let Err(e) = server.send_response(mme_peer, &bri) {
        log::error!("Bearer Resource Failure Indication to {mme_peer} failed: {e}");
    }
}

/// Remove `bearer_ids` at the SGW-U (best effort: nothing waits for it) and here.
fn remove_bearers(sess_id: u64, bearer_ids: &[u64]) {
    if bearer_ids.is_empty() {
        return;
    }
    let ctx = sgwc_self();
    if let Some(sess) = ctx.sess_find_by_id(sess_id) {
        if let Err(e) = pfcp_path::send_bearer_to_modify_list_gating(
            &sess,
            bearer_ids,
            pfcp_modify::REMOVE,
            S11Continuation::None,
        ) {
            log::warn!("dedicated bearer removal at the SGW-U not sent: {e}");
        }
    }
    for &id in bearer_ids {
        ctx.bearer_remove(id);
    }
}

fn server() -> Option<GtpcServer> {
    crate::gtp_path::s11_server()
}

/// Step 1: the PGW's Create Bearer Request (`msg` from `pgw_peer`).
///
/// `command` is the (MME, S11 sequence) of the Command this request is the triggered
/// message of, when it is one (#591).
pub(crate) fn on_pgw_request(
    server: &GtpcServer,
    msg: &Gtp2Message,
    pgw_peer: SocketAddr,
    command: Option<(SocketAddr, u32, u32)>,
) {
    let ctx = sgwc_self();
    let pgw_seq = msg.header.sequence_number;
    let local_teid = msg.header.teid.unwrap_or(0);
    let refuse_now = |pgw_teid: u32, cause: u8| {
        answer_pgw(
            server,
            pgw_peer,
            pgw_seq,
            pgw_teid,
            cause,
            &[(None, 0, cause)],
        );
        fail_command(server, command, msg, cause);
    };
    // The S5-C TEID is the low 32 bits of the SEID (see `forward_pgw_bearer_procedure_to_mme`).
    let Some(sess) = ctx.sess_find_by_teid(local_teid) else {
        log::warn!(
            "Create Bearer Request from {pgw_peer} for S5-C TEID {local_teid:#x}: no session"
        );
        // TS 29.274 §7.2.4: "Context not found", to TEID 0 as the session is unknown.
        refuse_now(0, gtp_cause::CONTEXT_NOT_FOUND);
        return;
    };
    let requested = match requested_bearers(msg) {
        Ok(r) => r,
        Err(cause) => {
            log::warn!("Create Bearer Request from {pgw_peer} refused: cause {cause}");
            refuse_now(sess.pgw_s5c_teid, cause);
            return;
        }
    };
    let Some(gtpu_addr) = ctx.gtpu_address() else {
        log::error!("Create Bearer Request: no GTP-U address configured");
        refuse_now(sess.pgw_s5c_teid, gtp_cause::NO_RESOURCES_AVAILABLE);
        return;
    };
    // #1283 (after the request's own checks): the session's Sxa establishment is still in flight (no SGW-U SEID):
    // hold the request until it completes, rather than modifying SEID 0.
    if sess.sgwu_sxa_seid == 0 {
        log::info!(
            "Create Bearer Request from {pgw_peer} (seq {pgw_seq}): session {} is still being \
             established at the SGW-U; held",
            sess.id
        );
        let expired: Vec<Held> = {
            let mut list = held();
            let (old, kept): (Vec<_>, Vec<_>) =
                list.drain(..).partition(|h| h.at.elapsed() >= HOLD_MAX);
            *list = kept;
            list.push(Held {
                sess_id: sess.id,
                msg: msg.clone(),
                pgw_peer,
                command,
                at: std::time::Instant::now(),
            });
            old
        };
        refuse_held(expired);
        return;
    }

    let mut bearer_ids = Vec::new();
    for r in &requested {
        let Some(mut bearer) = ctx.bearer_add(sess.id) else {
            remove_bearers_locally(&bearer_ids);
            refuse_now(sess.pgw_s5c_teid, gtp_cause::NO_RESOURCES_AVAILABLE);
            return;
        };
        bearer.ebi = 0;
        bearer.qci = r.qos.qci;
        bearer.arp_priority_level = r.qos.pl;
        bearer.arp_pci = r.qos.pci;
        bearer.arp_pvi = r.qos.pvi;
        // As Create Session stores them: the wire values.
        bearer.mbr_ul = r.qos.mbr_ul;
        bearer.mbr_dl = r.qos.mbr_dl;
        bearer.gbr_ul = r.qos.gbr_ul;
        bearer.gbr_dl = r.qos.gbr_dl;
        ctx.bearer_update(&bearer);
        for tunnel in [
            ctx.dl_tunnel_in_bearer(bearer.id),
            ctx.ul_tunnel_in_bearer(bearer.id),
        ]
        .into_iter()
        .flatten()
        {
            let mut tunnel = tunnel;
            tunnel.local_teid = ctx.next_gtpu_teid();
            tunnel.pdr_id = Some(ctx.next_pdr_id());
            tunnel.far_id = Some(ctx.next_far_id());
            tunnel.local_addr = Some(gtpu_addr);
            ctx.tunnel_update(&tunnel);
        }
        // The uplink forwards to the PGW's S5/S8-U F-TEID. The downlink has no endpoint
        // yet, so its FAR buffers (`sxa_build::apply_action_for`).
        if let Some(mut ul) = ctx.ul_tunnel_in_bearer(bearer.id) {
            ul.remote_teid = r.pgw_s5u.teid;
            ul.remote_ip = TunnelIp {
                ipv4: r.pgw_s5u.ipv4_addr.map(std::net::Ipv4Addr::from),
                ipv6: r.pgw_s5u.ipv6_addr.map(std::net::Ipv6Addr::from),
            };
            ctx.tunnel_update(&ul);
        }
        bearer_ids.push(bearer.id);
    }

    let join = NEXT_JOIN.fetch_add(1, Ordering::SeqCst);
    let pending = PendingCreateBearer {
        pgw_peer,
        pgw_seq,
        pgw_teid: sess.pgw_s5c_teid,
        sess_id: sess.id,
        bearer_ids: bearer_ids.clone(),
        request: msg.clone(),
        command,
        s11: None,
        answer: None,
    };
    with_pending(|p| p.insert(join, pending.clone()));
    log::info!(
        "Create Bearer Request from PGW {pgw_peer} (seq {pgw_seq}): {} dedicated bearer(s) for \
         session {}; installing them at the SGW-U",
        bearer_ids.len(),
        sess.id
    );
    if let Err(e) = pfcp_path::send_bearer_to_modify_list_gating(
        &sess,
        &bearer_ids,
        pfcp_modify::CREATE,
        S11Continuation::CreateBearer { join },
    ) {
        log::error!("Create Bearer Request: the SGW-U rules were not sent: {e}");
        take(join);
        remove_bearers_locally(&bearer_ids);
        refuse(server, &pending, gtp_cause::NO_RESOURCES_AVAILABLE);
    }
}

fn remove_bearers_locally(bearer_ids: &[u64]) {
    let ctx = sgwc_self();
    for &id in bearer_ids {
        ctx.bearer_remove(id);
    }
}

/// Step 2: the SGW-U answered the install (`refused`: the cause it is refused with, or
/// `None` when accepted). On acceptance the request goes on to the MME.
pub(crate) fn installed(join: u64, refused: Option<u8>) {
    let Some(server) = server() else {
        log::error!("S11 server not open: Create Bearer {join} cannot continue");
        return;
    };
    let Some(mut p) = with_pending(|m| m.get(&join).cloned()) else {
        return;
    };
    if let Some(cause) = refused {
        log::error!(
            "Create Bearer Request from PGW {}: the SGW-U did not install the bearers (cause \
             {cause}); refused",
            p.pgw_peer
        );
        take(join);
        remove_bearers(p.sess_id, &p.bearer_ids);
        refuse(&server, &p, cause);
        return;
    }
    let ctx = sgwc_self();
    let ue = ctx
        .sess_find_by_id(p.sess_id)
        .and_then(|s| ctx.ue_find_by_id(s.sgwc_ue_id));
    let mme = p
        .command
        .map(|(peer, _, _)| peer)
        .or(ue.as_ref().and_then(|u| u.mme_addr));
    let (Some(ue), Some(mme_peer)) = (ue, mme) else {
        log::warn!("Create Bearer Request: no MME is recorded for the UE; refused");
        take(join);
        remove_bearers(p.sess_id, &p.bearer_ids);
        refuse(&server, &p, gtp_cause::CONTEXT_NOT_FOUND);
        return;
    };

    // The S11 request: the PGW's, re-addressed, with each Bearer Context's S1-U SGW
    // F-TEID added at instance 0.
    let mut relayed = p.request.clone();
    relayed.header.teid = Some(ue.mme_s11_teid);
    let seq = match p.command {
        Some((_, mme_seq, _)) => mme_seq,
        None => server.alloc_sequence_to(mme_peer),
    };
    relayed.header.sequence_number = seq;
    let originals: Vec<Gtp2BearerContextIe> = relayed
        .get_ies(Gtp2IeType::BearerContext as u8)
        .into_iter()
        .filter(|ie| ie.instance == 0)
        .filter_map(|ie| Gtp2BearerContextIe::decode(&Bytes::copy_from_slice(&ie.value)).ok())
        .collect();
    relayed.ies.retain(|ie| {
        !(ie.ie_type == Gtp2IeType::BearerContext as u8 && ie.instance == 0)
            && ie.ie_type != Gtp2IeType::Recovery as u8
    });
    for (mut bc, &bearer_id) in originals.into_iter().zip(p.bearer_ids.iter()) {
        bc.ies
            .retain(|ie| !(ie.ie_type == Gtp2IeType::FTeid as u8 && ie.instance == 0));
        if let Some(ul) = ctx.ul_tunnel_in_bearer(bearer_id) {
            if let Ok(ft) = s11_build::fteid(
                f_teid_interface::S1_U_SGW_GTP_U,
                ul.local_teid,
                ul.local_addr,
                ul.local_addr6,
            ) {
                bc.set_fteid(0, &ft);
            }
        }
        relayed.add_bearer_context(0, &bc);
    }

    p.s11 = Some((mme_peer, seq));
    with_pending(|m| m.insert(join, p.clone()));
    log::info!(
        "Relaying Create Bearer Request from PGW {} to MME {mme_peer} (S11 TEID {:#x}, seq \
         {seq}) with the S1-U SGW F-TEID of {} bearer(s)",
        p.pgw_peer,
        ue.mme_s11_teid,
        p.bearer_ids.len()
    );
    if let Err(e) = server.send_request(mme_peer, &relayed, p.sess_id) {
        log::error!("Create Bearer Request relay to MME {mme_peer} failed: {e}");
        take(join);
        remove_bearers(p.sess_id, &p.bearer_ids);
        refuse(&server, &p, gtp_cause::SYSTEM_FAILURE);
    }
}

/// Step 3: the MME's Create Bearer Response (`msg` from `mme_peer`), already matched to
/// its S11 transaction.
pub(crate) fn on_mme_answer(server: &GtpcServer, msg: &Gtp2Message, mme_peer: SocketAddr) {
    let seq = msg.header.sequence_number;
    let Some((join, mut p)) = with_pending(|m| {
        m.iter()
            .find(|(_, r)| r.s11 == Some((mme_peer, seq)))
            .map(|(j, r)| (*j, r.clone()))
    }) else {
        return;
    };
    let ctx = sgwc_self();
    let cause = msg
        .get_ie(Gtp2IeType::Cause as u8, 0)
        .and_then(|ie| ie.value.first().copied())
        .unwrap_or(gtp_cause::MANDATORY_IE_MISSING);
    let message_accepts = matches!(
        cause,
        gtp_cause::REQUEST_ACCEPTED | gtp_cause::REQUEST_ACCEPTED_PARTIALLY
    );
    let answered: Vec<Gtp2BearerContextIe> = msg
        .get_ies(Gtp2IeType::BearerContext as u8)
        .into_iter()
        .filter(|ie| ie.instance == 0)
        .filter_map(|ie| Gtp2BearerContextIe::decode(&Bytes::copy_from_slice(&ie.value)).ok())
        .collect();

    // Each of this request's bearers, matched to its answer by the S1-U SGW F-TEID the MME
    // echoes (instance 1), else by position.
    let mut outcomes: Vec<(u64, u8, u8)> = Vec::new();
    let mut accepted = Vec::new();
    let mut refused = Vec::new();
    for (n, &bearer_id) in p.bearer_ids.iter().enumerate() {
        let ul_teid = ctx.ul_tunnel_in_bearer(bearer_id).map(|t| t.local_teid);
        let bc = answered
            .iter()
            .find(|bc| {
                bc.fteid(1)
                    .ok()
                    .flatten()
                    .is_some_and(|f| Some(f.teid) == ul_teid)
            })
            .or_else(|| answered.get(n));
        let ebi = bc.and_then(|bc| bc.ebi().ok()).unwrap_or(0);
        let bearer_cause = bc
            .and_then(|bc| bc.cause().ok().flatten())
            .map(|c| c.cause)
            .unwrap_or(cause);
        let enb = bc.and_then(|bc| bc.fteid(0).ok().flatten());
        let ebi_free = ctx
            .bearer_find_by_sess_ebi(p.sess_id, ebi)
            .is_none_or(|b| b.id == bearer_id);
        match enb {
            Some(enb)
                if message_accepts
                    && bearer_cause == gtp_cause::REQUEST_ACCEPTED
                    && (5..=15).contains(&ebi)
                    && ebi_free =>
            {
                if let Some(mut bearer) = ctx.bearer_find_by_id(bearer_id) {
                    bearer.ebi = ebi;
                    ctx.bearer_update(&bearer);
                }
                if let Some(mut dl) = ctx.dl_tunnel_in_bearer(bearer_id) {
                    dl.remote_teid = enb.teid;
                    dl.remote_ip = TunnelIp {
                        ipv4: enb.ipv4_addr.map(std::net::Ipv4Addr::from),
                        ipv6: enb.ipv6_addr.map(std::net::Ipv6Addr::from),
                    };
                    ctx.tunnel_update(&dl);
                }
                outcomes.push((bearer_id, ebi, gtp_cause::REQUEST_ACCEPTED));
                accepted.push(bearer_id);
            }
            _ => {
                let c = if bearer_cause == gtp_cause::REQUEST_ACCEPTED {
                    // Accepted without what makes it usable: no eNB F-TEID, or an EBI
                    // that is not a free EPS bearer identity of the PDN connection.
                    gtp_cause::MANDATORY_IE_INCORRECT
                } else {
                    bearer_cause
                };
                outcomes.push((bearer_id, ebi, c));
                refused.push(bearer_id);
            }
        }
    }
    log::info!(
        "Create Bearer Response from MME {mme_peer} (seq {seq}): cause {cause}, {} accepted, {} \
         refused",
        accepted.len(),
        refused.len()
    );
    remove_bearers(p.sess_id, &refused);

    let pgw_cause = match (accepted.is_empty(), refused.is_empty()) {
        (true, _) if message_accepts => gtp_cause::REQUEST_REJECTED_REASON_NOT_SPECIFIED,
        (true, _) => cause,
        (false, true) => gtp_cause::REQUEST_ACCEPTED,
        (false, false) => gtp_cause::REQUEST_ACCEPTED_PARTIALLY,
    };
    if accepted.is_empty() {
        take(join);
        let bearers: Vec<(Option<u64>, u8, u8)> = outcomes
            .iter()
            .map(|&(id, e, c)| (Some(id), e, c))
            .collect();
        answer_pgw(
            server, p.pgw_peer, p.pgw_seq, p.pgw_teid, pgw_cause, &bearers,
        );
        return;
    }
    p.answer = Some((pgw_cause, outcomes));
    p.bearer_ids = accepted.clone();
    with_pending(|m| m.insert(join, p.clone()));
    let sent = ctx
        .sess_find_by_id(p.sess_id)
        .ok_or_else(|| "no session".to_string())
        .and_then(|sess| {
            pfcp_path::send_bearer_to_modify_list_gating(
                &sess,
                &accepted,
                pfcp_modify::ACTIVATE,
                S11Continuation::CreateBearerAnswer { join },
            )
        });
    if let Err(e) = sent {
        log::error!("Create Bearer: the downlink switch was not sent to the SGW-U: {e}");
        answered_by_sgwu(join, Some(gtp_cause::SYSTEM_FAILURE));
    }
}

/// Step 4: the SGW-U answered the downlink switch (`refused` as for [`installed`]).
pub(crate) fn answered_by_sgwu(join: u64, refused: Option<u8>) {
    let Some(server) = server() else {
        return;
    };
    let Some(p) = take(join) else {
        return;
    };
    let Some((mut cause, mut outcomes)) = p.answer.clone() else {
        return;
    };
    if let Some(c) = refused {
        log::error!(
            "Create Bearer: the SGW-U did not switch the downlink of {} bearer(s) the MME \
             accepted (cause {c}); the PGW is told they were not created, the MME still holds \
             them",
            p.bearer_ids.len()
        );
        remove_bearers(p.sess_id, &p.bearer_ids);
        for o in outcomes.iter_mut() {
            if o.2 == gtp_cause::REQUEST_ACCEPTED {
                o.2 = c;
            }
        }
        if outcomes.iter().all(|o| o.2 != gtp_cause::REQUEST_ACCEPTED) {
            cause = c;
        }
    }
    let bearers: Vec<(Option<u64>, u8, u8)> = outcomes
        .iter()
        .map(|&(id, e, c)| (Some(id), e, c))
        .collect();
    answer_pgw(&server, p.pgw_peer, p.pgw_seq, p.pgw_teid, cause, &bearers);
}

/// The MME never answered the relayed request (S11 N3 ran out): undo it, and tell the
/// PGW so (TS 29.274 §8.4, cause 100 "Remote peer not responding").
pub(crate) fn mme_silent(mme_peer: SocketAddr, s11_seq: u32) {
    let Some(join) = with_pending(|m| {
        m.iter()
            .find(|(_, r)| r.s11 == Some((mme_peer, s11_seq)))
            .map(|(j, _)| *j)
    }) else {
        return;
    };
    let Some(p) = take(join) else {
        return;
    };
    log::error!(
        "Create Bearer Request relayed to MME {mme_peer} (seq {s11_seq}) was never answered; \
         its bearers are removed"
    );
    remove_bearers(p.sess_id, &p.bearer_ids);
    if let Some(server) = server() {
        refuse(&server, &p, gtp_cause::REMOTE_PEER_NOT_RESPONDING);
    }
}

/// Drop every pending and held request. Test-only.
#[cfg(test)]
pub(crate) fn clear_for_test() {
    with_pending(|p| p.clear());
    held().clear();
}
