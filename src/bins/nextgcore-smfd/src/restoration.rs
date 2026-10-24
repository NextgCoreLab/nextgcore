//! Restoration signalling: telling consumers about resources this SMF can no
//! longer honour (issue #193, TS 23.527, TS 29.244 §5.22, TS 29.500 §6.5).
//!
//! # The gap this closes
//!
//! The SMF already *detects* that a UPF has gone: `check_peer_restart` compares
//! the peer's Recovery Time Stamp, `teardown_association` flushes the PFCP
//! session map, and #191 made both survive an SMF restart by persisting the
//! stamps alongside the sessions. What none of that did was tell **anyone**.
//!
//! The AMF holds an `smContextStatusUri` for every PDU session it created. When
//! the UPF restarts, every one of those sessions is gone at the user plane — and
//! before this module the SMF discarded them locally, logged a count, and left
//! the AMF believing in N contexts that cannot carry a packet. The AMF discovers
//! it on the next request, as a 404 with no explanation, or never.
//!
//! # When the signal is emitted
//!
//! #193's pre-check asks for a choice between notifying **at boot** for
//! everything that failed to restore, and notifying **lazily** on the first
//! request that touches a missing resource, and asks that the choice be applied
//! uniformly. The rule applied here is one step behind that dichotomy and
//! subsumes it: **notify at the point where the SMF has EVIDENCE that a resource
//! cannot be served.** Which of the two the answer looks like then depends on
//! where the evidence comes from, and for an SMF there are three places:
//!
//! 1. **At boot, for a session whose `PolicyBinding` record did not survive the
//!    restore.** This needs no peer: a session with no PCF association, no
//!    authorized QoS and no FSM state cannot be modified or cleanly released, and
//!    that is known the moment the snapshot is read.
//!    [`notify_unrestorable_at_boot`].
//! 2. **On the first association, when the peer's Recovery Time Stamp has
//!    changed** (or the association is released). Every session on that UPF is
//!    gone as a set — TS 23.527 §4.2. [`notify_sessions_unrecoverable`].
//! 3. **On a request the UPF answers with `Session context not found`** (cause
//!    65). That one session is gone and the others are not — TS 29.244 §7.5.3.1.
//!    [`reconcile_session_not_found`].
//!
//! The reason (2) is not folded into (1) is the substance of the choice: **at boot
//! the SMF does not know whether the UPF still holds the restored sessions.** It
//! has a session map and a set of stamps; only the first Association Setup says
//! which incarnation of the UPF answered. A boot-time burst for those would have
//! to guess — "assume everything survived" is today's silence, and "assume nothing
//! did" releases sessions that are perfectly alive, which is worse than the defect.
//!
//! So (1) is eager because its evidence is local, and (2) and (3) are lazy because
//! theirs is not. TS 29.500 §6.5 permits either reading; this one has the property
//! that every notification the SMF sends is backed by something it actually knows.
//!
//! # Persistence is not the gate
//!
//! #193's criterion 4 asks that an NF with no durable store "behaves as today"
//! and that this issue "must not make the memory-only path chattier". Boot
//! satisfies that exactly: with no store there is nothing restored and nothing
//! is emitted, which [`crate::tests`] asserts.
//!
//! A live UPF restart is treated differently, deliberately. The AMF's stale view
//! does not depend on whether the SMF wrote a file — a memory-only SMF with 200
//! live sessions strands 200 AMF contexts just as thoroughly — so gating the
//! signal on a persistence setting would leave the shipped default carrying the
//! defect this issue exists to remove. The extra traffic is one POST per session
//! that was previously being discarded in silence, which is the required
//! signalling rather than chatter.

use crate::context::smf_self;

/// TS 29.244 §8.2.1 cause 65: the UPF has no context for the F-SEID in the
/// request. For a session the SMF believes in, this is the per-session
/// equivalent of a peer restart.
pub const PFCP_CAUSE_SESSION_CONTEXT_NOT_FOUND: u8 = 65;

/// The TS 29.502 `resourceStatus` for a PDU session that no longer exists.
const RESOURCE_STATUS_RELEASED: &str = "RELEASED";

/// Every `(sm_context_ref, smContextStatusUri)` the SMF could notify, plus a
/// count of the sessions that have no URI to notify.
///
/// Read under both locks and returned as owned data, because the caller then
/// awaits an HTTP POST per entry and `std::sync::RwLock` guards must not be held
/// across an await.
fn notifiable_sessions(scope: Option<&SessionScope>) -> (Vec<(String, String)>, usize) {
    let global = smf_self();
    let Ok(ctx) = global.read() else {
        return (Vec::new(), 0);
    };
    let refs: Vec<String> = match ctx.pfcp_sessions.read() {
        Ok(sessions) => sessions
            .keys()
            .filter(|r| scope.is_none_or(|sc| sc.refs.contains(*r)))
            .cloned()
            .collect(),
        Err(_) => return (Vec::new(), 0),
    };
    let bindings = match ctx.policy_bindings.read() {
        Ok(b) => b,
        Err(_) => return (Vec::new(), refs.len()),
    };
    let mut notifiable = Vec::new();
    let mut silent = 0usize;
    for r in refs {
        match bindings
            .get(&r)
            .and_then(|b| b.sm_context_status_uri.clone())
        {
            Some(uri) => notifiable.push((r, uri)),
            None => silent += 1,
        }
    }
    (notifiable, silent)
}

/// The SUPI and PSI a session's release command is addressed to, when the binding
/// carries both.
fn lookup_ue(sm_context_ref: &str) -> Option<(String, u8)> {
    let global = smf_self();
    let ctx = global.read().ok()?;
    let bindings = ctx.policy_bindings.read().ok()?;
    let b = bindings.get(sm_context_ref)?;
    (!b.supi.is_empty() && b.psi != 0).then(|| (b.supi.clone(), b.psi))
}

/// Every `sm_context_ref` mapped to `upf_seid`.
///
/// A scan rather than a second index: the N4 request path knows the SEID but not
/// the SM context reference, and one reverse lookup on a session-scoped error is
/// not worth a map that every establishment and release would have to keep in
/// step with the first one.
///
/// **All** matches, not the first. A UPF allocates one F-SEID per session, so in
/// a healthy deployment this returns at most one — but if the SMF's map has two
/// references claiming the same SEID, it cannot tell them apart, and the UPF has
/// just said that SEID has no context. Every entry claiming it is therefore
/// wrong, and picking one arbitrarily would make the result depend on `HashMap`
/// iteration order. That is not hypothetical: it made this module's own N4-level
/// test fail 1 run in 5 against a stand-in UPF that hands out a constant SEID.
fn sm_context_refs_for_seid(upf_seid: u64) -> Vec<String> {
    let global = smf_self();
    let Ok(ctx) = global.read() else {
        return Vec::new();
    };
    let Ok(sessions) = ctx.pfcp_sessions.read() else {
        return Vec::new();
    };
    let mut refs: Vec<String> = sessions
        .iter()
        .filter(|(_, seid)| **seid == upf_seid)
        .map(|(r, _)| r.clone())
        .collect();
    // Deterministic order, so the log and the notification sequence are stable.
    refs.sort();
    refs
}

/// Tell every AMF that holds a status callback that its PDU sessions on this UPF
/// are released, because the UPF can no longer honour them (TS 23.527 §4.2).
///
/// Call this **before** flushing the session map: the join from session to
/// callback URI runs through `pfcp_sessions`, so an emptied map has nobody to
/// notify. Returns the number of notifications sent.
///
/// Best-effort per consumer, like every other status notification here: a
/// transport failure is logged and the remaining consumers are still told. The
/// local flush is the caller's job and happens regardless — a session the UPF has
/// dropped is gone whether or not the AMF can be reached.
pub async fn notify_sessions_unrecoverable(reason: &str) -> usize {
    notify_sessions_unrecoverable_in(reason, None).await
}

/// The sessions one UPF's teardown concerns (#720): the 5G SM context references
/// and EPC session ids whose PFCP session lives on that UPF. `None` in the
/// functions below means every session.
#[derive(Debug, Default, Clone)]
pub struct SessionScope {
    pub refs: std::collections::HashSet<String>,
    pub epc_sess_ids: std::collections::HashSet<u64>,
    /// The SMF-side N4 SEIDs of all of them, whose UPF bindings the teardown drops.
    pub seids: std::collections::HashSet<u64>,
}

/// [`notify_sessions_unrecoverable`] for the sessions in `scope` only (#720).
pub async fn notify_sessions_unrecoverable_in(reason: &str, scope: Option<&SessionScope>) -> usize {
    let (total, releases) = begin_unrecoverable_release(reason, scope);
    let _ = releases.await;
    total
}

/// Start releasing the sessions in `scope` (all, for `None`) that can no longer be
/// honoured, and return at once: `(how many are being released, the fan-out)`.
///
/// #721: which sessions, and their callbacks, are decided here, synchronously, so
/// the caller may flush the session map as soon as this returns. The per-session
/// work (an N1N2MessageTransfer per UE, up to its connect and request timeouts)
/// runs in the returned task. A caller on the N4 receive task drops the handle:
/// awaiting it there stalled every PFCP message from every UPF, and the restarted
/// UPF's own Heartbeat Response, for the length of the whole fan-out.
pub fn begin_unrecoverable_release(
    reason: &str,
    scope: Option<&SessionScope>,
) -> (usize, tokio::task::JoinHandle<()>) {
    let (notifiable, silent) = notifiable_sessions(scope);
    if notifiable.is_empty() && silent == 0 {
        return (0, tokio::spawn(async {}));
    }
    log::warn!(
        "PFCP restoration ({reason}): {} PDU session(s) can no longer be honoured; notifying \
         {} AMF status callback(s), {} session(s) have none so their consumer will not learn \
         of this from us",
        notifiable.len() + silent,
        notifiable.len(),
        silent
    );
    let total = notifiable.len();
    let reason = reason.to_string();
    // #718 review m2: a bounded parallel fan-out. One sequential POST per session
    // could not finish inside a pod's termination grace period with many UEs, and
    // the UEs after the SIGKILL heard nothing. Progress is logged, so an operator
    // can see how many were left if it is cut short anyway.
    let fan_out = tokio::spawn(async move {
        let permits = std::sync::Arc::new(tokio::sync::Semaphore::new(RELEASE_FANOUT));
        let mut releases = tokio::task::JoinSet::new();
        for (sm_context_ref, uri) in notifiable {
            let Ok(permit) = permits.clone().acquire_owned().await else {
                break;
            };
            let reason = reason.clone();
            releases.spawn(async move {
                let _permit = permit;
                release_one_unrecoverable(&sm_context_ref, &uri, &reason).await;
            });
        }
        let mut done = 0usize;
        while releases.join_next().await.is_some() {
            done += 1;
            if done.is_multiple_of(100) || done == total {
                log::info!(
                    "PFCP restoration ({reason}): {done}/{total} PDU session release(s) sent, \
                     {} remaining",
                    total - done
                );
            }
        }
    });
    (total, fan_out)
}

/// How many PDU session releases [`notify_sessions_unrecoverable`] has in flight at
/// once (#718 review m2).
const RELEASE_FANOUT: usize = 16;

/// Release one PDU session that can no longer be honoured.
async fn release_one_unrecoverable(sm_context_ref: &str, status_uri: &str, reason: &str) {
    // #667: release the session through the UE, asking it to come back (#39),
    // so the user plane is rebuilt on the restarted UPF. A binding without the
    // UE's identity cannot be addressed that way, and gets the bare RELEASED
    // status the AMF was sent before #667.
    match lookup_ue(sm_context_ref) {
        Some((supi, psi)) => {
            log::warn!(
                "releasing sm_context_ref={sm_context_ref} after {reason}: PDU Session \
                 Release Command #39 (reactivation requested) to {supi} PSI {psi} via {status_uri}",
                status_uri = nextgcore_sbi::log_redact::redact_last_segment(status_uri)
            );
            crate::release_for_reactivation(sm_context_ref, status_uri, &supi, psi).await;
        }
        None => {
            // #854: no UE identity to release through, so the release is finished here:
            // the binding, session and address, the SM policy and the effects at the
            // other NFs go now, and the AMF is told RELEASED. Before, only the
            // notification went, and the binding and its SM policy stayed for good.
            log::warn!(
                "releasing sm_context_ref={sm_context_ref} after {reason} locally (no SUPI/PSI \
                 to release it through); notifying {status_uri}",
                status_uri = nextgcore_sbi::log_redact::redact_last_segment(status_uri)
            );
            crate::complete_sm_context_release(sm_context_ref);
            crate::send_sm_context_status_notification(
                Some(status_uri),
                RESOURCE_STATUS_RELEASED,
                Some(reason),
            )
            .await;
        }
    }
}

/// #687: release every EPC PDN connection after its PGW-U restarted or released
/// the association. Returns how many Delete Bearer Requests were sent.
///
/// The EPC counterpart of [`notify_sessions_unrecoverable`]. A PDN connection that
/// arrived over S5/S8 has no SM context, no `pfcp_sessions` entry and no AMF to
/// notify, so that path counted none of them ("0 stale sessions flushed"). The UE
/// kept a default bearer whose PGW-U session no longer existed, and nobody told the
/// SGW, the MME or the UE.
///
/// TS 23.007 §16 and TS 29.244 §5.22: every PFCP session on a restarted UP function
/// is gone. The PGW-C deletes the PDN connection toward the SGW with a Delete Bearer
/// Request naming the default bearer (Linked EBI), so the whole PDN connection goes
/// (TS 29.274 §7.2.9.2), with cause "Reactivation requested" (TS 29.274 §8.4). The
/// MME can then have the UE re-attach and build the user plane again on the
/// restarted PGW-U, the way #667 has a 5G UE re-establish its PDU session.
///
/// The session is removed here rather than on the Delete Bearer Response. Nothing
/// can be kept for it: the user plane is already gone, and a late or missing answer
/// must not hold the UE's address out of the pool.
pub async fn release_epc_pdn_connections(reason: &str) -> usize {
    release_epc_pdn_connections_in(reason, None).await
}

/// [`release_epc_pdn_connections`] for the PDN connections in `scope` only (#720).
pub async fn release_epc_pdn_connections_in(reason: &str, scope: Option<&SessionScope>) -> usize {
    let Some(server) = crate::gtp_path::s5s8_server() else {
        return 0;
    };
    release_epc_pdn_connections_scoped(server, crate::gtp_path::GTPC_PORT, reason, scope).await
}

/// [`release_epc_pdn_connections`] through `server`, addressing each SGW-C at
/// `sgw_port` (TS 29.274 §4.1 fixes it at 2123; tests bind an ephemeral one).
pub async fn release_epc_pdn_connections_via(
    server: &crate::gtp_path::S5S8Server,
    sgw_port: u16,
    reason: &str,
) -> usize {
    release_epc_pdn_connections_scoped(server, sgw_port, reason, None).await
}

/// [`release_epc_pdn_connections_via`] for the PDN connections in `scope` (#720).
pub async fn release_epc_pdn_connections_scoped(
    server: &crate::gtp_path::S5S8Server,
    sgw_port: u16,
    reason: &str,
    scope: Option<&SessionScope>,
) -> usize {
    let global = smf_self();
    // Owned data, so no guard is held across the sends below.
    let targets: Vec<(crate::context::SmfSess, u8)> = match global.read() {
        Ok(ctx) => ctx
            .sess_find_all_by(|s| {
                s.epc
                    && s.sgw_s5c_teid != 0
                    && s.sgw_s5c_ip.ipv4.is_some()
                    && scope.is_none_or(|sc| sc.epc_sess_ids.contains(&s.id))
            })
            .into_iter()
            .filter_map(|sess| {
                // The default bearer is the one the Create Session Request created,
                // so the first one linked into the session.
                let ebi = sess
                    .bearer_ids
                    .first()
                    .and_then(|id| ctx.bearer_find_by_id(*id))
                    .map(|b| b.ebi)?;
                Some((sess, ebi))
            })
            .collect(),
        Err(_) => return 0,
    };
    if targets.is_empty() {
        return 0;
    }
    log::warn!(
        "PFCP restoration ({reason}): {} EPC PDN connection(s) lost their PGW-U session; \
         deleting each toward its SGW with cause Reactivation requested",
        targets.len()
    );
    let mut sent = 0;
    for (sess, ebi) in &targets {
        let Some(sgw_ip) = sess.sgw_s5c_ip.ipv4 else {
            continue;
        };
        let peer = std::net::SocketAddr::new(std::net::IpAddr::V4(sgw_ip), sgw_port);
        let request = crate::gtp_build::build_delete_bearer_request(
            sess,
            *ebi,
            *ebi,
            None,
            Some(crate::gtp_build::Gtp2Cause::ReactivationRequested),
        );
        let seq = server
            .send_request(
                peer,
                request,
                crate::gtp_build::gtp2_message_type::DELETE_BEARER_REQUEST,
            )
            .await;
        log::warn!(
            "S5/S8 Delete Bearer Request to {peer} (seq {seq}): LBI {ebi}, SGW TEID {:#x}, \
             PDN address {:?}, after {reason}",
            sess.sgw_s5c_teid,
            sess.ipv4_addr
        );
        if let Ok(ctx) = global.read() {
            ctx.sess_remove(sess.id);
        }
        sent += 1;
    }
    sent
}

/// Reconcile one session the UPF says it does not have (TS 29.244 §7.5.3.1
/// cause 65): drop it locally, persist the smaller map, and tell the AMF.
///
/// This is the disagreement #191 made reachable. A restored session map plus an
/// UNCHANGED peer Recovery Time Stamp means no restart was detected, so the SMF
/// keeps every restored session — and it is still possible for one of them to be
/// absent at the UPF: the UPF was reconfigured, the session was removed out of
/// band, or the snapshot predates a UPF-side deletion the SMF never saw. The
/// only evidence is the UPF's own cause code on the next request that touches it,
/// and before this the SMF logged that cause and left the session in the map, so
/// every later request repeated the same round trip to the same answer.
///
/// Returns `true` when a session was found and dropped.
pub async fn reconcile_session_not_found(upf_seid: u64) -> bool {
    let refs = sm_context_refs_for_seid(upf_seid);
    if refs.is_empty() {
        log::debug!(
            "UPF reported no context for SEID {upf_seid:#x} and the SMF holds no session for \
             it either -- nothing to reconcile"
        );
        return false;
    }
    for sm_context_ref in refs {
        reconcile_one(upf_seid, sm_context_ref).await;
    }
    true
}

/// Drop one session and notify its consumer. Split out of
/// [`reconcile_session_not_found`] so the multi-match case is a loop rather than a
/// duplicated body.
async fn reconcile_one(upf_seid: u64, sm_context_ref: String) {
    // #912 review M3: the whole release, not only the PFCP map entry: the binding,
    // session and address (`take_sm_context`), the SM policy and the effects at the
    // UDM, the EASDF and the AMF (`complete_sm_context_release`). Before, the context
    // stayed half-live and every later request for it found it.
    let uri = crate::complete_sm_context_release(&sm_context_ref);
    log::warn!(
        "UPF has no context for SEID {upf_seid:#x} (sm_context_ref={sm_context_ref}): the SMF \
         and the UPF disagreed about a session. Released locally so it is no longer treated \
         as live; the UE must re-establish."
    );
    crate::send_sm_context_status_notification(
        uri.as_deref(),
        RESOURCE_STATUS_RELEASED,
        Some("session context not found at the UPF"),
    )
    .await;
}

/// Tell the consumers of sessions this boot could not fully reinstate, and stop
/// believing in those sessions (#193 criterion 1).
///
/// This is the one signal that genuinely belongs at **boot** rather than at first
/// association, because it needs no evidence from the UPF: a restored PDU session
/// whose `PolicyBinding` record did not survive has no PCF association, no
/// authorized QoS and no GSM FSM state, so the SMF cannot modify it, cannot
/// release it cleanly, and cannot answer an update about it. That is known the
/// moment the snapshot is read.
///
/// The callback was salvaged from the raw JSON of the failed record
/// (`SmfContext::restore_from`), which is what makes the notification possible at
/// all — the typed value is precisely what could not be read.
///
/// Drains the pending list, so a second call is a no-op: re-notifying on a later
/// boot would tell an AMF about a context it released long ago.
///
/// Returns `(notified, unnotifiable)`.
pub async fn notify_unrestorable_at_boot() -> (usize, usize) {
    let global = smf_self();
    let pending: Vec<crate::context::UnrestorableSession> = {
        let Ok(ctx) = global.read() else {
            return (0, 0);
        };
        let taken = match ctx.unrestorable_sessions.write() {
            Ok(mut p) => std::mem::take(&mut *p),
            Err(_) => Vec::new(),
        };
        taken
    };
    if pending.is_empty() {
        return (0, 0);
    }

    let mut notified = 0usize;
    let mut unnotifiable = 0usize;
    for entry in &pending {
        // Drop the session first: it is unusable either way, and leaving it in the
        // map after telling the AMF it is RELEASED would be the two ends
        // disagreeing in the opposite direction.
        if let Ok(ctx) = global.read() {
            let removed = {
                match ctx.pfcp_sessions.write() {
                    Ok(mut sessions) => sessions.remove(&entry.sm_context_ref).is_some(),
                    Err(_) => false,
                }
            };
            if !removed {
                log::debug!(
                    "unrestorable session {} was already gone",
                    entry.sm_context_ref
                );
            }
            // #912 review M3: the restored allocation goes back too; nothing else
            // holds it, since the binding that named it could not be read.
            if let Some(ip) = entry.ue_ip {
                ctx.ipv4_pool.release(std::net::Ipv4Addr::from(ip));
            }
            // After the write guard drops: `persist` re-reads the same map.
            ctx.persist();
        }
        match entry.status_uri.as_deref() {
            Some(status_uri) => {
                log::warn!(
                    "boot restoration: sm_context_ref={} cannot be served ({}); telling {status_uri} it \
                     is released",
                    entry.sm_context_ref,
                    entry.reason, status_uri = nextgcore_sbi::log_redact::redact_last_segment(status_uri)
                );
                crate::send_sm_context_status_notification(
                    Some(status_uri),
                    RESOURCE_STATUS_RELEASED,
                    Some(&entry.reason),
                )
                .await;
                notified += 1;
            }
            None => {
                log::error!(
                    "boot restoration: sm_context_ref={} cannot be served ({}) and NO status \
                     callback could be salvaged from its record, so its AMF will not learn of \
                     this from us -- it will see a 404 on its next request",
                    entry.sm_context_ref,
                    entry.reason
                );
                unnotifiable += 1;
            }
        }
    }
    log::warn!(
        "boot restoration: {} unusable session(s) dropped, {notified} consumer(s) notified, \
         {unnotifiable} with no reachable consumer",
        pending.len()
    );
    (notified, unnotifiable)
}

/// Whether a PFCP cause means "this session does not exist at the UPF", and the
/// SMF should therefore stop believing in it.
///
/// Only cause 65. The other rejection causes (mandatory IE missing, rule
/// creation failed, no established association) are about the *request*, and
/// dropping the session on those would destroy a live session over a malformed
/// message — the failure mode this deliberately does not have.
pub fn cause_means_session_gone(cause: u8) -> bool {
    cause == PFCP_CAUSE_SESSION_CONTEXT_NOT_FOUND
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::PROCESS_STATE_TEST_LOCK;
    use crate::pfcp_path::N4_TEST_LOCK;
    use nextgcore_sbi::message::{SbiRequest, SbiResponse};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    /// A stand-in AMF that records every `SmContextStatusNotification` body it is
    /// POSTed, so the assertions are about the WIRE rather than a log line — which
    /// #193's criterion 1 asks for explicitly.
    struct StatusSink {
        server: nextgcore_sbi::server::SbiServer,
        uri: String,
        bodies: Arc<Mutex<Vec<serde_json::Value>>>,
        posts: Arc<AtomicUsize>,
        /// (path, [(content id, bytes)]) per request, for the multipart N1N2
        /// transfer (#667).
        requests: Arc<Mutex<Vec<(String, Vec<(String, Vec<u8>)>)>>>,
    }

    async fn start_status_sink() -> StatusSink {
        // The stand-in AMF is plaintext loopback, i.e. a dev-profile deployment
        // (issue #63). Declared rather than inherited: the default Production
        // profile makes `sbi_peer_client_config` attempt TLS and the POST never
        // arrives -- which is exactly how these tests first failed.
        nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
        let bodies: Arc<Mutex<Vec<serde_json::Value>>> = Arc::new(Mutex::new(Vec::new()));
        let posts = Arc::new(AtomicUsize::new(0));
        let requests: Arc<Mutex<Vec<(String, Vec<(String, Vec<u8>)>)>>> =
            Arc::new(Mutex::new(Vec::new()));
        let sink_bodies = Arc::clone(&bodies);
        let sink_posts = Arc::clone(&posts);
        let sink_requests = Arc::clone(&requests);
        let (server, addr) =
            nextgcore_sbi::test_support::sbi_server_on_free_port(move |req: SbiRequest| {
                let bodies = Arc::clone(&sink_bodies);
                let posts = Arc::clone(&sink_posts);
                let requests = Arc::clone(&sink_requests);
                async move {
                    posts.fetch_add(1, Ordering::SeqCst);
                    if let Ok(mut r) = requests.lock() {
                        r.push((
                            req.header.uri.clone(),
                            req.http
                                .parts
                                .iter()
                                .map(|p| {
                                    (p.content_id.clone().unwrap_or_default(), p.data.to_vec())
                                })
                                .collect(),
                        ));
                    }
                    if let Some(c) = req.http.content.as_deref() {
                        if let Ok(v) = serde_json::from_str::<serde_json::Value>(c) {
                            if let Ok(mut b) = bodies.lock() {
                                b.push(v);
                            }
                        }
                    }
                    SbiResponse::with_status(204)
                }
            })
            .await;
        StatusSink {
            server,
            uri: format!("http://127.0.0.1:{}/callbacks/sm-status", addr.port()),
            bodies,
            posts,
            requests,
        }
    }

    /// Seed one restored PDU session: a `pfcp_sessions` entry plus the policy
    /// binding that carries the AMF's callback, which is the join
    /// `notifiable_sessions` walks.
    fn seed_session(sm_context_ref: &str, upf_seid: u64, status_uri: Option<&str>) {
        let global = crate::context::smf_self();
        let ctx = global.read().expect("smf context");
        ctx.pfcp_sessions
            .write()
            .expect("sessions")
            .insert(sm_context_ref.to_string(), upf_seid);
        let mut b = crate::context::PolicyBinding::snapshot_default();
        b.supi = "imsi-001010000000193".to_string();
        b.psi = 7;
        b.sm_context_status_uri = status_uri.map(str::to_string);
        ctx.policy_bindings
            .write()
            .expect("bindings")
            .insert(sm_context_ref.to_string(), b);
    }

    fn forget_session(sm_context_ref: &str) {
        let global = crate::context::smf_self();
        let ctx = global.read().expect("smf context");
        {
            let mut s = ctx.pfcp_sessions.write().expect("sessions");
            s.remove(sm_context_ref);
        }
        let mut b = ctx.policy_bindings.write().expect("bindings");
        b.remove(sm_context_ref);
    }

    fn session_is_live(sm_context_ref: &str) -> bool {
        let global = crate::context::smf_self();
        let Ok(ctx) = global.read() else { return false };
        let Ok(s) = ctx.pfcp_sessions.read() else {
            return false;
        };
        s.contains_key(sm_context_ref)
    }

    #[test]
    fn only_cause_65_means_the_session_is_gone() {
        assert!(cause_means_session_gone(65));
        // 1 Request accepted, 64 Request rejected, 66 Mandatory IE missing,
        // 72 No established PFCP association, 74 Rule creation failure.
        for other in [0u8, 1, 64, 66, 67, 68, 69, 70, 71, 72, 73, 74, 255] {
            assert!(
                !cause_means_session_gone(other),
                "cause {other} must not drop a session: it is about the request, not the \
                 session's existence"
            );
        }
    }

    /// #193 criterion 1, as #667 refined it: a session on a restarted UPF is
    /// released THROUGH THE UE, observed on the wire. The AMF gets one
    /// N1N2MessageTransfer carrying the PDU SESSION RELEASE COMMAND with 5GSM cause
    /// #39 (reactivation requested) and the N2 PDU Session Resource Release
    /// Command, and T3592 guards it.
    ///
    /// Before #667 the AMF was sent only a RELEASED status notification: it dropped
    /// its record and the UE kept a dead session forever.
    #[tokio::test]
    async fn an_unrecoverable_session_is_released_through_the_ue_for_reactivation() {
        let _state = PROCESS_STATE_TEST_LOCK.lock().await;
        // These tests seed and read `pfcp_sessions`, which `N4_TEST_LOCK` also
        // guards: `teardown_association` calls `clear_pfcp_sessions`, wiping the map
        // for the WHOLE process. Documented order: ambient first, N4 second.
        let _n4 = N4_TEST_LOCK.lock().await;
        let sink = start_status_sink().await;
        seed_session("restore-notify-ref", 0x0193_0001, Some(&sink.uri));

        let notified = notify_sessions_unrecoverable("peer restarted").await;

        let t3592_armed = crate::cancel_gsm_timer_for_test("restore-notify-ref");
        let binding_kept = crate::lookup_policy_binding_for_test("restore-notify-ref");
        forget_session("restore-notify-ref");
        sink.server.stop().await.expect("stop sink");

        assert_eq!(notified, 1, "the one session with a callback is released");
        assert_eq!(
            sink.posts.load(Ordering::SeqCst),
            1,
            "exactly one POST, on the wire"
        );
        let requests = sink.requests.lock().expect("requests");
        let (path, parts) = &requests[0];
        assert_eq!(
            path, "/namf-comm/v1/ue-contexts/imsi-001010000000193/n1-n2-messages",
            "Namf_Communication_N1N2MessageTransfer to the serving AMF"
        );
        let n1 = &parts
            .iter()
            .find(|(id, _)| id == "n1SmMsg")
            .expect("the N1 part")
            .1;
        assert_eq!(
            n1[..5],
            [
                0x2E,
                7,
                0,
                crate::gsm_build::message_type::PDU_SESSION_RELEASE_COMMAND,
                crate::policy::gsm_cause::REACTIVATION_REQUESTED
            ],
            "5GSM, PSI 7, PTI 0 (network-initiated), RELEASE COMMAND, cause #39"
        );
        assert!(
            parts
                .iter()
                .any(|(id, data)| id == "n2SmInfo" && !data.is_empty()),
            "the N2 PDU Session Resource Release Command transfer rides along"
        );
        let bodies = sink.bodies.lock().expect("bodies");
        assert_eq!(
            bodies[0]["n2InfoContainer"]["smInfo"]["n2InfoContent"]["ngapIeType"],
            "PDU_RES_REL_CMD"
        );
        assert!(t3592_armed, "T3592 guards the release command");
        assert!(
            binding_kept,
            "the SM context lives until the UE's RELEASE COMPLETE or T3592 exhaustion"
        );
    }

    /// #667: when the UE never answers, the final T3592 expiry releases the session
    /// locally and tells the AMF RELEASED (TS 24.501 §6.3.3.5).
    #[tokio::test]
    async fn an_unanswered_release_is_released_locally_and_the_amf_told() {
        let _state = PROCESS_STATE_TEST_LOCK.lock().await;
        let _n4 = N4_TEST_LOCK.lock().await;
        let sink = start_status_sink().await;
        seed_session("restore-t3592-ref", 0x0193_0004, Some(&sink.uri));

        crate::abandon_gsm_procedure_for_test("restore-t3592-ref").await;

        let binding_kept = crate::lookup_policy_binding_for_test("restore-t3592-ref");
        forget_session("restore-t3592-ref");
        sink.server.stop().await.expect("stop sink");

        assert!(!binding_kept, "the SM context is gone");
        let bodies = sink.bodies.lock().expect("bodies");
        assert_eq!(bodies.len(), 1);
        assert_eq!(bodies[0]["statusInfo"]["resourceStatus"], "RELEASED");
    }

    /// The other half of criterion 1, and the reason the count is reported
    /// separately: a session whose consumer supplied no `smContextStatusUri`
    /// cannot be told anything. The SMF must say so rather than appear to have
    /// notified everyone.
    #[tokio::test]
    async fn a_session_with_no_callback_is_counted_not_notified() {
        let _state = PROCESS_STATE_TEST_LOCK.lock().await;
        // These tests seed and read `pfcp_sessions`, which `N4_TEST_LOCK` also
        // guards: `teardown_association` calls `clear_pfcp_sessions`, wiping the map
        // for the WHOLE process. Taking only the ambient lock left a window in which
        // an `pfcp_path` sibling cleared the map between the seed and the assertion,
        // which made `two_references_on_one_seid_are_both_reconciled` fail about 1
        // whole-workspace run in 12. Documented order: ambient first, N4 second.
        let _n4 = N4_TEST_LOCK.lock().await;
        let sink = start_status_sink().await;
        seed_session("restore-silent-ref", 0x0193_0002, None);

        let notified = notify_sessions_unrecoverable("peer restarted").await;

        forget_session("restore-silent-ref");
        sink.server.stop().await.expect("stop sink");

        assert_eq!(
            notified, 0,
            "there is no callback, so nothing was notified -- and the count must not pretend \
             otherwise"
        );
        assert_eq!(sink.posts.load(Ordering::SeqCst), 0);
    }

    /// #193 criterion 3: the SMF/UPF disagreement. A session the SMF restored and
    /// the UPF does not have must stop being treated as live, and the AMF must be
    /// told.
    ///
    /// This is the case an unchanged Recovery Time Stamp cannot catch: no restart
    /// happened, so #191's interlock leaves the session in place, and the UPF's
    /// own cause code is the only evidence.
    #[tokio::test]
    async fn a_session_the_upf_does_not_have_is_dropped_and_the_amf_told() {
        let _state = PROCESS_STATE_TEST_LOCK.lock().await;
        // These tests seed and read `pfcp_sessions`, which `N4_TEST_LOCK` also
        // guards: `teardown_association` calls `clear_pfcp_sessions`, wiping the map
        // for the WHOLE process. Taking only the ambient lock left a window in which
        // an `pfcp_path` sibling cleared the map between the seed and the assertion,
        // which made `two_references_on_one_seid_are_both_reconciled` fail about 1
        // whole-workspace run in 12. Documented order: ambient first, N4 second.
        let _n4 = N4_TEST_LOCK.lock().await;
        let sink = start_status_sink().await;
        seed_session("restore-disagree-ref", 0x0193_0003, Some(&sink.uri));
        assert!(
            session_is_live("restore-disagree-ref"),
            "precondition: the SMF believes in the session"
        );

        let reconciled = reconcile_session_not_found(0x0193_0003).await;

        let still_live = session_is_live("restore-disagree-ref");
        forget_session("restore-disagree-ref");
        sink.server.stop().await.expect("stop sink");

        assert!(reconciled, "the session was found and reconciled");
        assert!(
            !still_live,
            "a session the UPF has no context for must not be treated as live"
        );
        assert_eq!(sink.posts.load(Ordering::SeqCst), 1);
        let bodies = sink.bodies.lock().expect("bodies");
        assert_eq!(bodies[0]["statusInfo"]["resourceStatus"], "RELEASED");
        assert_eq!(
            bodies[0]["statusInfo"]["cause"], "session context not found at the UPF",
            "the cause distinguishes a per-session disagreement from a peer restart"
        );
    }

    /// Reconciliation is scoped to the one session the UPF named. A restarted UPF
    /// is a set; a cause-65 answer is emphatically not, and dropping the siblings
    /// would turn one stale entry into an outage.
    #[tokio::test]
    async fn reconciliation_touches_only_the_named_session() {
        let _state = PROCESS_STATE_TEST_LOCK.lock().await;
        // These tests seed and read `pfcp_sessions`, which `N4_TEST_LOCK` also
        // guards: `teardown_association` calls `clear_pfcp_sessions`, wiping the map
        // for the WHOLE process. Taking only the ambient lock left a window in which
        // an `pfcp_path` sibling cleared the map between the seed and the assertion,
        // which made `two_references_on_one_seid_are_both_reconciled` fail about 1
        // whole-workspace run in 12. Documented order: ambient first, N4 second.
        let _n4 = N4_TEST_LOCK.lock().await;
        let sink = start_status_sink().await;
        seed_session("restore-scope-gone", 0x0193_0004, Some(&sink.uri));
        seed_session("restore-scope-alive", 0x0193_0005, Some(&sink.uri));

        reconcile_session_not_found(0x0193_0004).await;

        let gone = session_is_live("restore-scope-gone");
        let alive = session_is_live("restore-scope-alive");
        let posts = sink.posts.load(Ordering::SeqCst);
        forget_session("restore-scope-gone");
        forget_session("restore-scope-alive");
        sink.server.stop().await.expect("stop sink");

        assert!(!gone);
        assert!(
            alive,
            "the sibling session is live at the UPF and must be left alone"
        );
        assert_eq!(posts, 1, "one session gone means one notification, not two");
    }

    /// Two references claiming ONE SEID are both reconciled, not one of them
    /// arbitrarily.
    ///
    /// The SMF cannot tell them apart and the UPF has just said that SEID has no
    /// context, so both are wrong. Picking the first match would make the outcome
    /// depend on `HashMap` iteration order -- which is how this module's N4-level
    /// test failed 1 run in 5 before the lookup was made total.
    #[tokio::test]
    async fn two_references_on_one_seid_are_both_reconciled() {
        let _state = PROCESS_STATE_TEST_LOCK.lock().await;
        // These tests seed and read `pfcp_sessions`, which `N4_TEST_LOCK` also
        // guards: `teardown_association` calls `clear_pfcp_sessions`, wiping the map
        // for the WHOLE process. Taking only the ambient lock left a window in which
        // an `pfcp_path` sibling cleared the map between the seed and the assertion,
        // which made `two_references_on_one_seid_are_both_reconciled` fail about 1
        // whole-workspace run in 12. Documented order: ambient first, N4 second.
        let _n4 = N4_TEST_LOCK.lock().await;
        let sink = start_status_sink().await;
        seed_session("restore-dup-a", 0x0193_0006, Some(&sink.uri));
        seed_session("restore-dup-b", 0x0193_0006, Some(&sink.uri));

        let reconciled = reconcile_session_not_found(0x0193_0006).await;

        let a = session_is_live("restore-dup-a");
        let b = session_is_live("restore-dup-b");
        let posts = sink.posts.load(Ordering::SeqCst);
        forget_session("restore-dup-a");
        forget_session("restore-dup-b");
        sink.server.stop().await.expect("stop sink");

        assert!(reconciled);
        assert!(!a && !b, "both entries claim a SEID the UPF does not have");
        assert_eq!(posts, 2, "each consumer is told about its own context");
    }

    /// An unknown SEID reconciles nothing and notifies nobody. Without this, a
    /// cause-65 answer to a request for a session the SMF has already released
    /// would send the AMF a second RELEASED for a context it has forgotten.
    #[tokio::test]
    async fn an_unknown_seid_reconciles_nothing() {
        let _state = PROCESS_STATE_TEST_LOCK.lock().await;
        // These tests seed and read `pfcp_sessions`, which `N4_TEST_LOCK` also
        // guards: `teardown_association` calls `clear_pfcp_sessions`, wiping the map
        // for the WHOLE process. Taking only the ambient lock left a window in which
        // an `pfcp_path` sibling cleared the map between the seed and the assertion,
        // which made `two_references_on_one_seid_are_both_reconciled` fail about 1
        // whole-workspace run in 12. Documented order: ambient first, N4 second.
        let _n4 = N4_TEST_LOCK.lock().await;
        let sink = start_status_sink().await;

        let reconciled = reconcile_session_not_found(0xdead_beef_0193).await;

        sink.server.stop().await.expect("stop sink");
        assert!(!reconciled);
        assert_eq!(sink.posts.load(Ordering::SeqCst), 0);
    }

    /// #193 criterion 1, the boot half: a restored session the SMF cannot serve
    /// produces a notification to the consumer whose callback the restore
    /// salvaged, and the session stops being treated as live.
    #[tokio::test]
    async fn boot_notifies_the_consumer_of_a_session_it_cannot_serve() {
        let _state = PROCESS_STATE_TEST_LOCK.lock().await;
        // These tests seed and read `pfcp_sessions`, which `N4_TEST_LOCK` also
        // guards: `teardown_association` calls `clear_pfcp_sessions`, wiping the map
        // for the WHOLE process. Taking only the ambient lock left a window in which
        // an `pfcp_path` sibling cleared the map between the seed and the assertion,
        // which made `two_references_on_one_seid_are_both_reconciled` fail about 1
        // whole-workspace run in 12. Documented order: ambient first, N4 second.
        let _n4 = N4_TEST_LOCK.lock().await;
        let sink = start_status_sink().await;
        // The shape `restore_from` produces: a session in the map, no binding, and
        // a callback salvaged from the record that could not be typed.
        {
            let global = crate::context::smf_self();
            let ctx = global.read().expect("smf context");
            {
                let mut sessions = ctx.pfcp_sessions.write().expect("sessions");
                sessions.insert("boot-orphan-ref".to_string(), 0x0193_3000);
            }
            let mut pending = ctx.unrestorable_sessions.write().expect("pending");
            pending.push(crate::context::UnrestorableSession {
                ue_ip: None,
                sm_context_ref: "boot-orphan-ref".to_string(),
                status_uri: Some(sink.uri.clone()),
                reason: "policy binding could not be restored: test".to_string(),
            });
        }

        let (notified, unnotifiable) = notify_unrestorable_at_boot().await;

        let still_live = session_is_live("boot-orphan-ref");
        forget_session("boot-orphan-ref");
        let posts = sink.posts.load(Ordering::SeqCst);
        let bodies = sink.bodies.lock().expect("bodies").clone();
        sink.server.stop().await.expect("stop sink");

        assert_eq!((notified, unnotifiable), (1, 0));
        assert!(
            !still_live,
            "a session with no policy binding cannot be modified or released, so keeping it in \
             the map would leave the SMF believing in something it cannot serve"
        );
        assert_eq!(posts, 1);
        assert_eq!(bodies[0]["statusInfo"]["resourceStatus"], "RELEASED");
        assert_eq!(
            bodies[0]["statusInfo"]["cause"], "policy binding could not be restored: test",
            "the cause names the restore failure, which is what an operator needs"
        );
    }

    /// The same path when NO callback could be salvaged. The session is still
    /// dropped -- it is unusable either way -- and the count reports honestly that
    /// nobody was told, instead of the notifier appearing to have succeeded.
    #[tokio::test]
    async fn boot_reports_a_session_whose_consumer_cannot_be_reached() {
        let _state = PROCESS_STATE_TEST_LOCK.lock().await;
        // These tests seed and read `pfcp_sessions`, which `N4_TEST_LOCK` also
        // guards: `teardown_association` calls `clear_pfcp_sessions`, wiping the map
        // for the WHOLE process. Taking only the ambient lock left a window in which
        // an `pfcp_path` sibling cleared the map between the seed and the assertion,
        // which made `two_references_on_one_seid_are_both_reconciled` fail about 1
        // whole-workspace run in 12. Documented order: ambient first, N4 second.
        let _n4 = N4_TEST_LOCK.lock().await;
        let sink = start_status_sink().await;
        {
            let global = crate::context::smf_self();
            let ctx = global.read().expect("smf context");
            {
                let mut sessions = ctx.pfcp_sessions.write().expect("sessions");
                sessions.insert("boot-mute-ref".to_string(), 0x0193_3001);
            }
            let mut pending = ctx.unrestorable_sessions.write().expect("pending");
            pending.push(crate::context::UnrestorableSession {
                ue_ip: None,
                sm_context_ref: "boot-mute-ref".to_string(),
                status_uri: None,
                reason: "policy binding could not be restored: test".to_string(),
            });
        }

        let (notified, unnotifiable) = notify_unrestorable_at_boot().await;

        let still_live = session_is_live("boot-mute-ref");
        forget_session("boot-mute-ref");
        let posts = sink.posts.load(Ordering::SeqCst);
        sink.server.stop().await.expect("stop sink");

        assert_eq!((notified, unnotifiable), (0, 1));
        assert!(!still_live, "unusable either way");
        assert_eq!(posts, 0);
    }

    /// The pending list is DRAINED, so a second pass is silent. Re-notifying on a
    /// later boot would tell an AMF about a context it released long ago.
    #[tokio::test]
    async fn boot_notification_happens_once() {
        let _state = PROCESS_STATE_TEST_LOCK.lock().await;
        // These tests seed and read `pfcp_sessions`, which `N4_TEST_LOCK` also
        // guards: `teardown_association` calls `clear_pfcp_sessions`, wiping the map
        // for the WHOLE process. Taking only the ambient lock left a window in which
        // an `pfcp_path` sibling cleared the map between the seed and the assertion,
        // which made `two_references_on_one_seid_are_both_reconciled` fail about 1
        // whole-workspace run in 12. Documented order: ambient first, N4 second.
        let _n4 = N4_TEST_LOCK.lock().await;
        let sink = start_status_sink().await;
        {
            let global = crate::context::smf_self();
            let ctx = global.read().expect("smf context");
            {
                let mut sessions = ctx.pfcp_sessions.write().expect("sessions");
                sessions.insert("boot-once-ref".to_string(), 0x0193_3002);
            }
            let mut pending = ctx.unrestorable_sessions.write().expect("pending");
            pending.push(crate::context::UnrestorableSession {
                ue_ip: None,
                sm_context_ref: "boot-once-ref".to_string(),
                status_uri: Some(sink.uri.clone()),
                reason: "policy binding could not be restored: test".to_string(),
            });
        }

        let first = notify_unrestorable_at_boot().await;
        let second = notify_unrestorable_at_boot().await;

        forget_session("boot-once-ref");
        let posts = sink.posts.load(Ordering::SeqCst);
        sink.server.stop().await.expect("stop sink");

        assert_eq!(first, (1, 0));
        assert_eq!(second, (0, 0), "the list must be drained, not re-read");
        assert_eq!(posts, 1);
    }

    /// #912 review N3: boot frees the restored address of a session whose binding could
    /// not be read (salvaged as `ue_ip`); nothing else holds it.
    #[tokio::test]
    async fn boot_frees_the_address_of_an_unrestorable_session() {
        let _state = PROCESS_STATE_TEST_LOCK.lock().await;
        let _n4 = N4_TEST_LOCK.lock().await;
        let ip = std::net::Ipv4Addr::new(10, 45, 9, 31);
        {
            let global = crate::context::smf_self();
            let ctx = global.read().expect("smf context");
            assert!(
                ctx.ipv4_pool.reserve(ip),
                "precondition: the restored allocation"
            );
            ctx.unrestorable_sessions.write().expect("pending").push(
                crate::context::UnrestorableSession {
                    ue_ip: Some(ip.octets()),
                    sm_context_ref: "boot-free-ref".to_string(),
                    status_uri: None,
                    reason: "policy binding could not be restored: test".to_string(),
                },
            );
        }
        let _ = notify_unrestorable_at_boot().await;
        let global = crate::context::smf_self();
        let ctx = global.read().expect("smf context");
        let freed = ctx.ipv4_pool.reserve(ip);
        ctx.ipv4_pool.release(ip);
        assert!(freed, "the address is back in the pool");
    }

    /// #193 criterion 4: with nothing restored there is nothing to signal.
    ///
    /// The shipped default configures no state file, so a fresh SMF has an empty
    /// session map and this path must be silent — the criterion's "must not make
    /// the memory-only path chattier", asserted rather than asserted-about.
    #[tokio::test]
    async fn nothing_restored_means_nothing_emitted() {
        let _state = PROCESS_STATE_TEST_LOCK.lock().await;
        // These tests seed and read `pfcp_sessions`, which `N4_TEST_LOCK` also
        // guards: `teardown_association` calls `clear_pfcp_sessions`, wiping the map
        // for the WHOLE process. Taking only the ambient lock left a window in which
        // an `pfcp_path` sibling cleared the map between the seed and the assertion,
        // which made `two_references_on_one_seid_are_both_reconciled` fail about 1
        // whole-workspace run in 12. Documented order: ambient first, N4 second.
        let _n4 = N4_TEST_LOCK.lock().await;
        let sink = start_status_sink().await;
        // No seeding: this is boot with no snapshot.
        let drained = {
            let global = crate::context::smf_self();
            let ctx = global.read().expect("ctx");
            let mut sessions = ctx.pfcp_sessions.write().expect("sessions");
            let drained: Vec<(String, u64)> = sessions.drain().collect();
            drained
        };

        let notified = notify_sessions_unrecoverable("boot with no snapshot").await;

        // Put back whatever a sibling test had in flight.
        {
            let global = crate::context::smf_self();
            let ctx = global.read().expect("smf context");
            let mut sessions = ctx.pfcp_sessions.write().expect("sessions");
            sessions.extend(drained);
        }
        sink.server.stop().await.expect("stop sink");

        assert_eq!(notified, 0);
        assert_eq!(
            sink.posts.load(Ordering::SeqCst),
            0,
            "an SMF with no restored sessions must emit nothing at all"
        );
    }
}
