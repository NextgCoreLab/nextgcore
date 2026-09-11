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
            // Modification responses gate no S11 procedure today (see the spec's
            // ceiling); the cause is logged so a rejected modification is not silent.
            let cause = find_cause(body);
            if cause != Some(sxa_handler::pfcp_cause::REQUEST_ACCEPTED) {
                log::warn!(
                    "PFCP Session Modification for session {sess_id} was REJECTED: cause={cause:?}"
                );
            }
        }
        other => log::warn!("Unexpected PFCP response type {other} for session {sess_id}"),
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
