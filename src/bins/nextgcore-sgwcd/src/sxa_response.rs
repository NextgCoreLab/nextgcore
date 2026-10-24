//! What an Sxa response means for the S11 procedure that is waiting for it (#54).
//!
//! TS 23.401 §5.3.2.1: the Serving GW returns the Create Session Response **after** the
//! user plane has been provisioned, and TS 29.274 §7.2.2 makes `Request accepted` mean the
//! request was actually fulfilled. Before this module the S11 responses were sent from the
//! GTP-C dispatch with a hard-coded `REQUEST_ACCEPTED`, before any PFCP response existed —
//! and `sxa_handler::handle_session_establishment_response`, the function that maps the
//! PFCP cause, had no caller outside tests.
//!
//! This is the join: the PFCP transaction carries what the S11 answer needs
//! ([`crate::pfcp_path::S11Continuation`]), the response is decoded and dispatched into
//! `sxa_handler`, and the answer the MME gets is the one the SGW-U actually gave.

use bytes::Bytes;

use nextgcore_gtp::v2::header::Gtp2MessageType;
use nextgcore_pfcp::message::{SessionDeletionResponse, SessionEstablishmentResponse};

use crate::context::sgwc_self;
use crate::pfcp_path::{pfcp_msg_type, S11Continuation};
use crate::s11_handler::gtp_cause;
use crate::sxa_handler::{self, HandlerResult};
use crate::{gtp_path, s11_build};

/// A PFCP response landed for a transaction that was gating an S11 procedure.
pub fn dispatch(sess_id: u64, continuation: S11Continuation, resp_type: u8, body: &[u8]) {
    match resp_type {
        pfcp_msg_type::SESSION_ESTABLISHMENT_RESPONSE => {
            establishment_response(sess_id, continuation, body)
        }
        pfcp_msg_type::SESSION_DELETION_RESPONSE => deletion_response(sess_id, continuation, body),
        pfcp_msg_type::SESSION_MODIFICATION_RESPONSE => {
            let cause = find_cause(body);
            if cause != Some(sxa_handler::pfcp_cause::REQUEST_ACCEPTED) {
                log::warn!(
                    "PFCP Session Modification for session {sess_id} was REJECTED: cause={cause:?}"
                );
            }
            // #48: ONE modification now gates an S11 procedure -- the indirect
            // forwarding install. Every other modification still gates nothing, which is
            // why this dispatches on the continuation rather than on the response.
            match continuation {
                S11Continuation::IndirectForwarding { .. } => {
                    indirect_forwarding_response(continuation, cause)
                }
                S11Continuation::ModifyBearer { join, sess_id } => {
                    let outcome = if cause == Some(sxa_handler::pfcp_cause::REQUEST_ACCEPTED) {
                        None
                    } else {
                        Some(gtp_cause::SYSTEM_FAILURE)
                    };
                    modify_bearer_session_done(join, sess_id, outcome);
                }
                _ => {}
            }
        }
        other => log::warn!("Unexpected PFCP response type {other} for session {sess_id}"),
    }
}

/// Answer the MME's Create Indirect Data Forwarding Tunnel Request now that the SGW-U
/// has spoken (#48).
///
/// The response is built by `s11_build`, not by [`answer`], because a bare cause is not
/// enough: TS 29.274 Table 7.2.19-2 wants the per-bearer forwarding F-TEIDs, and those
/// are the whole point of the procedure. A cause-only accept is what this used to send.
fn indirect_forwarding_response(continuation: S11Continuation, pfcp_cause: Option<u8>) {
    let S11Continuation::IndirectForwarding {
        peer,
        seq,
        teid,
        sgwc_ue_id,
    } = continuation
    else {
        return;
    };

    let accepted = pfcp_cause == Some(sxa_handler::pfcp_cause::REQUEST_ACCEPTED);
    let cause = if accepted {
        gtp_cause::REQUEST_ACCEPTED
    } else {
        log::warn!(
            "Create Indirect Data Forwarding Tunnel Response to {peer} carries a failure: the \
             SGW-U refused the forwarding rules (pfcp_cause={pfcp_cause:?})"
        );
        gtp_cause::SYSTEM_FAILURE
    };

    let Some(server) = gtp_path::s11_server() else {
        log::error!("S11 server not open: cannot answer {peer}");
        return;
    };
    match s11_build::build_create_indirect_data_forwarding_tunnel_response(sgwc_ue_id, seq, cause) {
        Ok(response) => {
            if let Err(e) = server.send_response(peer, &response) {
                log::error!("Indirect tunnel response to {peer} failed: {e}");
            }
        }
        Err(e) => {
            log::error!("Failed to build indirect tunnel response: {e}");
            answer(
                peer,
                Gtp2MessageType::CreateIndirectDataForwardingTunnelResponse,
                teid,
                seq,
                gtp_cause::SYSTEM_FAILURE,
            );
        }
    }
}

/// Answer the waiting S11 procedure with a SPECIFIC cause (#52).
///
/// [`fail`] answers `REMOTE_PEER_NOT_RESPONDING`, which is right when a peer went
/// silent. When the PGW answered and REFUSED, the MME is owed the PGW's own cause: the
/// difference between "the anchor did not reply" and "the anchor said no, because the
/// APN is unknown" is the difference between a retry and a fix.
pub fn fail_with_cause(continuation: S11Continuation, cause: u8) {
    match continuation {
        S11Continuation::None => {}
        S11Continuation::CreateSession { peer, seq, teid } => {
            answer(
                peer,
                Gtp2MessageType::CreateSessionResponse,
                teid,
                seq,
                cause,
            );
        }
        S11Continuation::DeleteSession {
            peer, seq, teid, ..
        } => {
            answer(
                peer,
                Gtp2MessageType::DeleteSessionResponse,
                teid,
                seq,
                cause,
            );
        }
        S11Continuation::IndirectForwarding {
            peer, seq, teid, ..
        } => {
            answer(
                peer,
                Gtp2MessageType::CreateIndirectDataForwardingTunnelResponse,
                teid,
                seq,
                cause,
            );
        }
        S11Continuation::ModifyBearer { join, sess_id } => {
            modify_bearer_session_done(join, sess_id, Some(cause));
        }
    }
}

/// The transaction never completed (T1 x N1 expiry, or a local error).
///
/// The MME is waiting. Answering now with a mapped cause is what stops the procedure
/// hanging until the MME's own GTP-C timer fires (TS 29.274 §7.6) — and
/// `REMOTE_PEER_NOT_RESPONDING` says which peer failed, rather than blaming the SGW-C.
pub fn fail(continuation: S11Continuation, reason: &str) {
    match continuation {
        S11Continuation::None => {}
        S11Continuation::CreateSession { peer, seq, teid } => {
            log::error!(
                "Create Session Response to {peer} carries a failure: the SGW-U never answered \
                 ({reason})"
            );
            answer(
                peer,
                Gtp2MessageType::CreateSessionResponse,
                teid,
                seq,
                gtp_cause::REMOTE_PEER_NOT_RESPONDING,
            );
        }
        S11Continuation::DeleteSession {
            peer,
            seq,
            teid,
            sess_id,
        } => {
            // The local context is deliberately KEPT: the SGW-U may still hold the
            // session, and removing ours would strand it there with nothing left to
            // delete it by (TS 23.007 §17).
            log::error!(
                "Delete Session Response to {peer} carries a failure: the SGW-U never answered \
                 ({reason}); session {sess_id} is KEPT so a retry can still reach it"
            );
            answer(
                peer,
                Gtp2MessageType::DeleteSessionResponse,
                teid,
                seq,
                gtp_cause::REMOTE_PEER_NOT_RESPONDING,
            );
        }
        S11Continuation::IndirectForwarding {
            peer, seq, teid, ..
        } => {
            // #48: the MME is waiting to send its Handover Command. Answering a failure
            // now lets the handover proceed WITHOUT forwarding, which loses buffered
            // downlink data -- but leaving the MME to time out loses the handover.
            log::error!(
                "Create Indirect Data Forwarding Tunnel Response to {peer} carries a failure: \
                 the SGW-U never installed the forwarding rules ({reason})"
            );
            answer(
                peer,
                Gtp2MessageType::CreateIndirectDataForwardingTunnelResponse,
                teid,
                seq,
                gtp_cause::REMOTE_PEER_NOT_RESPONDING,
            );
        }
        S11Continuation::ModifyBearer { join, sess_id } => {
            log::error!(
                "Modify Bearer: the SGW-U never answered the Session Modification of session \
                 {sess_id} ({reason}); its bearers are reported not modified"
            );
            modify_bearer_session_done(join, sess_id, Some(gtp_cause::REMOTE_PEER_NOT_RESPONDING));
        }
    }
}

// ============================================================================
// Modify Bearer Request waiting for the SGW-U (#838)
// ============================================================================

/// A Modify Bearer Request whose answer waits for one PFCP Session Modification
/// per session it touched.
#[derive(Debug, Clone)]
pub struct PendingModifyBearer {
    /// The MME and its request.
    pub peer: std::net::SocketAddr,
    pub seq: u32,
    pub mme_teid: u32,
    /// Sessions still waiting for the SGW-U, with the bearers each switches.
    pub waiting: std::collections::BTreeMap<u64, Vec<SwitchedBearer>>,
    /// (bearer id, EBI) of the bearers already settled as modified. The EBI is
    /// kept from when the request was parked, so a bearer deleted meanwhile is
    /// still named in the answer (#839 review).
    pub modified: Vec<(u64, u8)>,
    /// (EBI, cause) of the bearers not modified.
    pub marked_for_removal: Vec<(u8, u8)>,
}

/// A bearer a parked Modify Bearer Request switches, with the downlink endpoint
/// it had before, restored if the SGW-U does not switch it (#839 review).
#[derive(Debug, Clone)]
pub struct SwitchedBearer {
    pub bearer_id: u64,
    pub ebi: u8,
    /// The DL tunnel's (remote TEID, remote IP) before the request.
    pub previous: Option<(u32, crate::context::IpAddr)>,
    /// The DL tunnel's generation after this request wrote it: the rollback
    /// restores `previous` only while the tunnel is still at it (#937, #987
    /// review), so a later writer is never undone, even one that wrote the
    /// same values.
    pub written: u64,
}

static PENDING_MODIFY_BEARER: std::sync::Mutex<
    std::collections::BTreeMap<u64, PendingModifyBearer>,
> = std::sync::Mutex::new(std::collections::BTreeMap::new());
static NEXT_MODIFY_BEARER_JOIN: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

/// Park a Modify Bearer answer; returns its join id.
pub fn park_modify_bearer(pending: PendingModifyBearer) -> u64 {
    let join = NEXT_MODIFY_BEARER_JOIN.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    PENDING_MODIFY_BEARER
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(join, pending);
    join
}

/// Whether a Modify Bearer Request from `peer` at `seq` is already waiting for
/// the SGW-U: a retransmission is then not processed again (TS 29.274 §7.6).
pub fn modify_bearer_in_flight(peer: std::net::SocketAddr, seq: u32) -> bool {
    PENDING_MODIFY_BEARER
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .values()
        .any(|p| p.peer == peer && p.seq == seq)
}

/// Number of Modify Bearer answers waiting. Test/diagnostic.
pub fn modify_bearer_pending_count() -> usize {
    PENDING_MODIFY_BEARER
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .len()
}

/// One session of Modify Bearer `join` is settled: `failure` `None` means the
/// SGW-U switched its bearers, `Some(cause)` that it did not. When it is the last
/// session, the MME is answered: Request accepted when every bearer is modified,
/// Request accepted partially when some are, and the failure cause otherwise,
/// each bearer in Bearer Contexts modified or marked for removal (TS 29.274
/// Table 7.2.8-1).
pub fn modify_bearer_session_done(join: u64, sess_id: u64, failure: Option<u8>) {
    let done = {
        let mut map = PENDING_MODIFY_BEARER
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let Some(pending) = map.get_mut(&join) else {
            return;
        };
        let Some(bearers) = pending.waiting.remove(&sess_id) else {
            return;
        };
        let ctx = sgwc_self();
        match failure {
            None => {
                for b in bearers {
                    if ctx.bearer_find_by_id(b.bearer_id).is_some() {
                        pending.modified.push((b.bearer_id, b.ebi));
                    } else {
                        // Deleted while the modification was pending.
                        pending
                            .marked_for_removal
                            .push((b.ebi, gtp_cause::CONTEXT_NOT_FOUND));
                    }
                }
            }
            Some(cause) => {
                for b in bearers {
                    // #839 review: the SGW-U kept its FAR and the MME keeps the
                    // old eNB endpoint, so the SGW-C does too. Otherwise a later
                    // PFCP modification built from this tunnel would push an
                    // endpoint the MME never confirmed.
                    if let (Some((teid, ip)), Some(mut dl)) =
                        (b.previous, ctx.dl_tunnel_in_bearer(b.bearer_id))
                    {
                        let still_ours = dl.generation == b.written;
                        if still_ours {
                            dl.remote_teid = teid;
                            dl.remote_ip = ip;
                            ctx.tunnel_update(&dl);
                        } else {
                            log::info!(
                                "EBI {}: the DL endpoint changed after this Modify Bearer \
                                 Request; its refusal leaves the newer one",
                                b.ebi
                            );
                        }
                    }
                    pending.marked_for_removal.push((b.ebi, cause));
                }
            }
        }
        if pending.waiting.is_empty() {
            map.remove(&join)
        } else {
            None
        }
    };
    if let Some(pending) = done {
        answer_modify_bearer(&pending, failure);
    }
}

/// The parked Modify Bearer answer `join`, if still waiting. Test/diagnostic.
#[cfg(test)]
pub fn modify_bearer_pending(join: u64) -> Option<PendingModifyBearer> {
    PENDING_MODIFY_BEARER
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(&join)
        .cloned()
}

/// Send the Modify Bearer Response for a settled request.
pub fn answer_modify_bearer(pending: &PendingModifyBearer, last_failure: Option<u8>) {
    let cause = match (
        pending.modified.is_empty(),
        pending.marked_for_removal.is_empty(),
    ) {
        (false, true) => gtp_cause::REQUEST_ACCEPTED,
        (false, false) => gtp_cause::REQUEST_ACCEPTED_PARTIALLY,
        (true, _) => pending
            .marked_for_removal
            .iter()
            .map(|(_, c)| *c)
            .find(|c| *c != gtp_cause::CONTEXT_NOT_FOUND)
            .or(last_failure)
            .unwrap_or(gtp_cause::CONTEXT_NOT_FOUND),
    };
    log::info!(
        "Modify Bearer Response to {} (seq={}): cause {cause}, modified {} bearer(s), marked for \
         removal {:?}",
        pending.peer,
        pending.seq,
        pending.modified.len(),
        pending.marked_for_removal
    );
    let Some(server) = gtp_path::s11_server() else {
        log::error!("S11 server not open: cannot answer {}", pending.peer);
        return;
    };
    let response = s11_build::build_modify_bearer_response_per_bearer(
        pending.mme_teid,
        pending.seq,
        cause,
        &pending.modified,
        &pending.marked_for_removal,
    );
    if let Err(e) = server.send_response(pending.peer, &response) {
        log::error!("Modify Bearer Response to {} failed: {e}", pending.peer);
    }
}

fn establishment_response(sess_id: u64, continuation: S11Continuation, body: &[u8]) {
    let ctx = sgwc_self();
    let sess = ctx.sess_find_by_id(sess_id);

    let mut cursor = Bytes::copy_from_slice(body);
    let (pfcp_cause, up_f_seid) = match SessionEstablishmentResponse::decode(&mut cursor) {
        Ok(rsp) => (
            rsp.cause as u8,
            rsp.up_f_seid.as_ref().map(|f| f.seid).unwrap_or(0),
        ),
        Err(e) => {
            // A malformed response is not an accepted one. Mapping it to SYSTEM_FAILURE
            // rather than guessing keeps the "accepted means fulfilled" promise.
            log::warn!("Malformed Session Establishment Response for session {sess_id}: {e}");
            (sxa_handler::pfcp_cause::SYSTEM_FAILURE, 0)
        }
    };

    let result =
        sxa_handler::handle_session_establishment_response(sess.as_ref(), 0, pfcp_cause, up_f_seid);

    let S11Continuation::CreateSession { peer, seq, teid } = continuation else {
        return;
    };

    let cause = match result {
        HandlerResult::Error(cause) => cause,
        // `SendGtpToPgw` is what the handler returns on success: TS 23.401 §5.3.2.1 has
        // the SGW-C now send a Create Session Request to the PGW over S5/S8. That leg
        // does not exist in this tree (#52: no PGW client, and `pgw_addr` has no writer),
        // so the SGW-C answers the MME itself — which is the deployment shape this build
        // supports and is stated in the spec rather than left implied.
        _ => gtp_cause::REQUEST_ACCEPTED,
    };

    if cause != gtp_cause::REQUEST_ACCEPTED {
        log::warn!(
            "Create Session Response to {peer} carries cause={cause}: the SGW-U refused the \
             user plane (pfcp_cause={pfcp_cause})"
        );
        answer(
            peer,
            Gtp2MessageType::CreateSessionResponse,
            teid,
            seq,
            cause,
        );
        return;
    }

    // Re-read: `handle_session_establishment_response` stored the SGW-U's SEID.
    let Some(sess) = ctx.sess_find_by_id(sess_id) else {
        log::error!("Session {sess_id} vanished before its Create Session Response");
        answer(
            peer,
            Gtp2MessageType::CreateSessionResponse,
            teid,
            seq,
            gtp_cause::CONTEXT_NOT_FOUND,
        );
        return;
    };
    let Some(server) = gtp_path::s11_server() else {
        log::error!("S11 server not open: cannot answer the Create Session Request");
        return;
    };
    match s11_build::build_create_session_response(&sess, seq, server.restart_counter()) {
        Ok(response) => {
            if let Err(e) = server.send_response(peer, &response) {
                log::error!("Create Session Response to {peer} failed: {e}");
            } else {
                log::info!(
                    "Create Session Response to {peer} sent after the SGW-U accepted \
                     (up_seid=0x{up_f_seid:x})"
                );
            }
        }
        Err(e) => {
            log::error!("Failed to build Create Session Response: {e}");
            answer(
                peer,
                Gtp2MessageType::CreateSessionResponse,
                teid,
                seq,
                gtp_cause::SYSTEM_FAILURE,
            );
        }
    }
}

fn deletion_response(sess_id: u64, continuation: S11Continuation, body: &[u8]) {
    let ctx = sgwc_self();
    let sess = ctx.sess_find_by_id(sess_id);

    let mut cursor = Bytes::copy_from_slice(body);
    let pfcp_cause = match SessionDeletionResponse::decode(&mut cursor) {
        Ok(rsp) => rsp.cause as u8,
        Err(e) => {
            log::warn!("Malformed Session Deletion Response for session {sess_id}: {e}");
            sxa_handler::pfcp_cause::SYSTEM_FAILURE
        }
    };

    let result = sxa_handler::handle_session_deletion_response(sess.as_ref(), 0, pfcp_cause);

    let S11Continuation::DeleteSession {
        peer,
        seq,
        teid,
        sess_id,
    } = continuation
    else {
        return;
    };

    match result {
        HandlerResult::Error(cause) => {
            // The local context is KEPT on a refusal, deliberately: removing it while the
            // SGW-U still holds the session would leak the user plane with nothing left
            // to address it by. The MME learns the truth and can retry.
            log::warn!(
                "Delete Session Response to {peer} carries cause={cause}: the SGW-U refused \
                 (pfcp_cause={pfcp_cause}); session {sess_id} is KEPT"
            );
            answer(
                peer,
                Gtp2MessageType::DeleteSessionResponse,
                teid,
                seq,
                cause,
            );
        }
        _ => {
            ctx.sess_remove(sess_id);
            log::info!(
                "Session {sess_id} removed after the SGW-U confirmed the deletion; answering \
                 {peer}"
            );
            answer(
                peer,
                Gtp2MessageType::DeleteSessionResponse,
                teid,
                seq,
                gtp_cause::REQUEST_ACCEPTED,
            );
        }
    }
}

/// A Downlink Data Report reached the SGW-C: page the UE (TS 23.401 §5.3.4.2).
///
/// #54: `gtp_path::send_downlink_data_notification` was reachable only from `mod tests`,
/// so downlink data for an idle UE produced no paging trigger at all.
pub fn downlink_data_notification(sess_id: u64, pdr_id: Option<u16>) {
    let ctx = sgwc_self();
    let Some(sess) = ctx.sess_find_by_id(sess_id) else {
        log::warn!("Downlink Data Report for unknown session {sess_id}");
        return;
    };
    // The report names a PDR; the DDN names a bearer. Prefer the bearer that owns the
    // reported PDR, and fall back to the session's first bearer when the report carried
    // no PDR id — a DDN for the wrong bearer pages the UE for the wrong EPS bearer.
    let bearer = sess
        .bearer_ids
        .iter()
        .filter_map(|id| ctx.bearer_find_by_id(*id))
        .find(|b| match pdr_id {
            Some(pdr) => [ctx.dl_tunnel_in_bearer(b.id), ctx.ul_tunnel_in_bearer(b.id)]
                .into_iter()
                .flatten()
                .any(|t| t.pdr_id == Some(pdr)),
            None => true,
        });
    let Some(bearer) = bearer else {
        log::warn!(
            "Downlink Data Report for session {sess_id} names PDR {pdr_id:?}, which no bearer \
             holds: no Downlink Data Notification sent"
        );
        return;
    };

    // TS 29.274 §7.2.11.2: the Data Notification Delay the MME last asked for throttles
    // the next DDN. Honoured here rather than at the report, because the delay is per UE.
    if let Some(ue) = ctx.ue_find_by_id(bearer.sgwc_ue_id) {
        if let Some(remaining) = ue.ddn_delay_remaining() {
            log::info!(
                "Downlink Data Notification for bearer {} throttled for {}ms more \
                 (Data Notification Delay, TS 29.274 §7.2.11.2)",
                bearer.id,
                remaining.as_millis()
            );
            return;
        }
    }

    let Some(server) = gtp_path::s11_server() else {
        log::error!("S11 server not open: cannot send a Downlink Data Notification");
        return;
    };
    match server.send_downlink_data_notification(None, &bearer) {
        Ok(seq) => {
            // Remember that one is outstanding, so a failure can be tied back to the
            // session whose buffered packets have to be discarded.
            if let Some(mut ue) = ctx.ue_find_by_id(bearer.sgwc_ue_id) {
                ue.ddn_outstanding_sess_id = Some(sess_id);
                ctx.ue_update(&ue);
            }
            log::info!(
                "Downlink Data Notification sent for bearer {} (seq={seq}) after a Downlink \
                 Data Report",
                bearer.id
            );
        }
        Err(e) => log::error!(
            "Downlink Data Notification for bearer {} failed: {e}",
            bearer.id
        ),
    }
}

/// The MME acknowledged a Downlink Data Notification (TS 29.274 §7.2.11.2). Issue #54.
///
/// Two things the handler used to drop on the floor:
///
/// - a **non-accepted cause** means the MME cannot serve the notification, and TS 23.401
///   §5.3.4.2 has the Serving GW delete the buffered packet(s) rather than hold them for a
///   UE that will not be paged;
/// - the **Data Notification Delay** throttles the next notification. It was parsed into
///   `ParsedDdnAck.data_notification_delay` and then discarded, so a busy idle UE could
///   produce a DDN per downlink packet — the storm the IE exists to suppress.
pub fn downlink_data_notification_ack(
    ue_id: Option<u64>,
    cause: u8,
    data_notification_delay: Option<u8>,
) {
    let Some(ue_id) = ue_id else { return };
    let ctx = sgwc_self();
    let Some(mut ue) = ctx.ue_find_by_id(ue_id) else {
        return;
    };

    ue.set_ddn_delay(data_notification_delay);
    let outstanding = ue.ddn_outstanding_sess_id.take();
    ctx.ue_update(&ue);

    if let Some(units) = data_notification_delay.filter(|u| *u > 0) {
        log::info!(
            "MME asked for a Data Notification Delay of {}ms: the next Downlink Data              Notification for UE {ue_id} waits that long (TS 29.274 §7.2.11.2)",
            units as u64 * 50
        );
    }

    if cause == gtp_cause::REQUEST_ACCEPTED {
        return;
    }
    discard_buffered(
        outstanding,
        ue_id,
        cause,
        "Downlink Data Notification Acknowledge",
    );
}

/// The MME sent a Downlink Data Notification Failure Indication (TS 29.274 §7.2.11.3):
/// the UE could not be reached, so the buffered packets are deleted (TS 23.401 §5.3.4.2).
pub fn downlink_data_notification_failed(ue_id: Option<u64>, cause: u8) {
    let Some(ue_id) = ue_id else { return };
    let ctx = sgwc_self();
    let Some(mut ue) = ctx.ue_find_by_id(ue_id) else {
        return;
    };
    let outstanding = ue.ddn_outstanding_sess_id.take();
    ctx.ue_update(&ue);
    discard_buffered(
        outstanding,
        ue_id,
        cause,
        "Downlink Data Notification Failure Indication",
    );
}

/// Ask the SGW-U to drop what it is holding for the session the DDN was about.
fn discard_buffered(sess_id: Option<u64>, ue_id: u64, cause: u8, because: &str) {
    let ctx = sgwc_self();
    // Fall back to every session of the UE when no DDN was recorded as outstanding: the
    // MME is telling us the UE cannot be reached, and holding packets for it either way is
    // the leak. Narrower would be better; silent would be wrong.
    let sessions: Vec<_> = match sess_id.and_then(|id| ctx.sess_find_by_id(id)) {
        Some(sess) => vec![sess],
        None => ctx
            .ue_find_by_id(ue_id)
            .map(|ue| {
                ue.sess_ids
                    .iter()
                    .filter_map(|id| ctx.sess_find_by_id(*id))
                    .collect()
            })
            .unwrap_or_default(),
    };
    if sessions.is_empty() {
        log::warn!("{because} (cause={cause}) for UE {ue_id}: no session to discard buffers on");
        return;
    }
    for sess in sessions {
        log::warn!(
            "{because} carried cause={cause}: discarding the packets the SGW-U buffered for              session {} (TS 23.401 §5.3.4.2)",
            sess.id
        );
        if let Err(e) = crate::pfcp_path::send_drop_buffered_packets(&sess) {
            log::error!(
                "Could not ask the SGW-U to discard session {}'s buffered packets: {e}. They                  stay buffered.",
                sess.id
            );
        }
    }
}

/// The Cause octet of a response body, without decoding the whole message.
fn find_cause(body: &[u8]) -> Option<u8> {
    let mut i = 0usize;
    while i + 4 <= body.len() {
        let ie_type = u16::from_be_bytes([body[i], body[i + 1]]);
        let len = u16::from_be_bytes([body[i + 2], body[i + 3]]) as usize;
        let value = &body[i + 4..(i + 4 + len).min(body.len())];
        // TS 29.244 §8.2.1: Cause is IE type 19.
        if ie_type == 19 && !value.is_empty() {
            return Some(value[0]);
        }
        i += 4 + len;
    }
    None
}

fn answer(
    peer: std::net::SocketAddr,
    response_type: Gtp2MessageType,
    teid: u32,
    seq: u32,
    cause: u8,
) {
    let Some(server) = gtp_path::s11_server() else {
        log::error!("S11 server not open: cannot answer {peer}");
        return;
    };
    let msg = s11_build::build_error_response(response_type as u8, teid, seq, cause, None);
    if let Err(e) = server.send_response(peer, &msg) {
        log::error!("Failed to answer {peer}: {e}");
    }
}

#[cfg(test)]
mod modify_bearer_tests {
    use super::*;

    /// #839 review: a bearer deleted while its PFCP modification was pending is
    /// still named in the answer, by the EBI kept when the request was parked,
    /// and as not found rather than modified.
    #[test]
    fn a_bearer_deleted_while_pending_is_named_by_its_parked_ebi() {
        // Real contexts (#937 review): a bearer that existed when the request
        // was parked and was deleted before the SGW-U answered. The parked
        // map is process-wide: serialised with the tests that count it.
        let _ambient = crate::pfcp_path::process_state_test_guard_blocking();
        let ctx = sgwc_self();
        let ue = ctx.ue_add(b"001010937000001").expect("ue");
        let sess = ctx.sess_add(ue.id, "internet").expect("sess");
        let mut bearer = ctx.bearer_add(sess.id).expect("bearer");
        bearer.ebi = 7;
        ctx.bearer_update(&bearer);
        let other = ctx.sess_add(ue.id, "ims").expect("sess");
        let gone = SwitchedBearer {
            bearer_id: bearer.id,
            ebi: 7,
            previous: None,
            written: 0,
        };
        let join = park_modify_bearer(PendingModifyBearer {
            peer: "127.0.0.1:2123".parse().unwrap(),
            seq: 0x839,
            mme_teid: 1,
            waiting: [(sess.id, vec![gone]), (other.id, vec![])]
                .into_iter()
                .collect(),
            modified: Vec::new(),
            marked_for_removal: Vec::new(),
        });
        ctx.bearer_remove(bearer.id);
        modify_bearer_session_done(join, sess.id, None);
        let pending = modify_bearer_pending(join).expect("one session still waiting");
        assert!(pending.modified.is_empty(), "not reported modified");
        assert_eq!(
            pending.marked_for_removal,
            vec![(7, gtp_cause::CONTEXT_NOT_FOUND)]
        );
        modify_bearer_session_done(join, other.id, None);
        assert!(modify_bearer_pending(join).is_none());
        ctx.ue_remove(ue.id);
    }

    /// #937 review: a refusal rolls the DL endpoint back only while the tunnel
    /// still holds what this request wrote; an endpoint a later request set
    /// meanwhile stays.
    /// #991 review: a writer that advances the generation marks a write even
    /// when it writes the endpoint the tunnel already holds.
    #[test]
    fn a_same_value_write_that_advances_the_generation_is_a_new_generation() {
        let _ambient = crate::pfcp_path::process_state_test_guard_blocking();
        let ctx = sgwc_self();
        let ue = ctx.ue_add(b"001010991000001").expect("ue");
        let sess = ctx.sess_add(ue.id, "internet").expect("sess");
        let bearer = ctx.bearer_add(sess.id).expect("bearer");
        let mut dl = ctx.dl_tunnel_in_bearer(bearer.id).expect("a DL tunnel");
        dl.remote_teid = 0x991;
        ctx.tunnel_update(&dl);
        let g0 = ctx.dl_tunnel_in_bearer(bearer.id).unwrap().generation;
        // The same value, no advance: no new generation.
        ctx.tunnel_update(&ctx.dl_tunnel_in_bearer(bearer.id).unwrap());
        assert_eq!(ctx.dl_tunnel_in_bearer(bearer.id).unwrap().generation, g0);
        // The same value, advanced (a Modify Bearer write): a new one.
        let mut same = ctx.dl_tunnel_in_bearer(bearer.id).unwrap();
        same.generation = same.generation.wrapping_add(1);
        ctx.tunnel_update(&same);
        assert_eq!(
            ctx.dl_tunnel_in_bearer(bearer.id).unwrap().generation,
            g0 + 1
        );
        ctx.ue_remove(ue.id);
    }

    #[test]
    fn a_refusal_does_not_undo_a_newer_endpoint() {
        let _ambient = crate::pfcp_path::process_state_test_guard_blocking();
        let ctx = sgwc_self();
        let ue = ctx.ue_add(b"001010937000002").expect("ue");
        let sess = ctx.sess_add(ue.id, "internet").expect("sess");
        let mut bearer = ctx.bearer_add(sess.id).expect("bearer");
        bearer.ebi = 5;
        ctx.bearer_update(&bearer);
        let write = |teid: u32| {
            let mut dl = ctx.dl_tunnel_in_bearer(bearer.id).expect("a DL tunnel");
            dl.remote_teid = teid;
            ctx.tunnel_update(&dl);
            ctx.dl_tunnel_in_bearer(bearer.id).unwrap().generation
        };
        let park = |written: u64| {
            park_modify_bearer(PendingModifyBearer {
                peer: "127.0.0.1:2123".parse().unwrap(),
                seq: 0x937,
                mme_teid: 1,
                waiting: [(
                    sess.id,
                    vec![SwitchedBearer {
                        bearer_id: bearer.id,
                        ebi: 5,
                        previous: Some((0x1111, Default::default())),
                        written,
                    }],
                )]
                .into_iter()
                .collect(),
                modified: Vec::new(),
                marked_for_removal: Vec::new(),
            })
        };
        // Still ours: rolled back.
        let g = write(0x2222);
        let join = park(g);
        modify_bearer_session_done(join, sess.id, Some(gtp_cause::SYSTEM_FAILURE));
        assert_eq!(
            ctx.dl_tunnel_in_bearer(bearer.id).unwrap().remote_teid,
            0x1111
        );
        // A later writer, even one that puts the same TEID back (A-B-A): left
        // alone, because the generation moved (#987 review).
        let g = write(0x2222);
        let _ = write(0x3333);
        let _ = write(0x2222);
        let join = park(g);
        modify_bearer_session_done(join, sess.id, Some(gtp_cause::SYSTEM_FAILURE));
        assert_eq!(
            ctx.dl_tunnel_in_bearer(bearer.id).unwrap().remote_teid,
            0x2222,
            "the newer writer's endpoint stays"
        );
        ctx.ue_remove(ue.id);
    }
}
