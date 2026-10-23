//! PDN GW initiated bearer deactivation towards the eNB and the UE (#734,
//! TS 23.401 §5.4.4.1 steps 4c-8, TS 24.301 §6.4.4).
//!
//! A Delete Bearer Request for a PDN connection that is not the UE's last, or
//! for dedicated bearers, used to be answered at once with the bearers deleted
//! in the MME only. The eNB kept the radio bearers and the UE kept the EPS
//! bearer contexts, so uplink on them was dropped at the SGW-U and the UE never
//! asked for the PDN again.
//!
//! For an ECM-CONNECTED UE this module now:
//! 1. sends an E-RAB RELEASE COMMAND carrying the ESM DEACTIVATE EPS BEARER
//!    CONTEXT REQUEST (step 4c): one for the PDN connection's default bearer
//!    (the UE then deletes every bearer of that PDN connection, TS 24.301
//!    §6.4.4.2), or one per dedicated bearer;
//! 2. arms T3495 per bearer (§6.4.4.2), retransmitting the request in DOWNLINK
//!    NAS TRANSPORT on expiry, and on the fifth expiry deactivating locally
//!    (§6.4.4.5 a);
//! 3. on DEACTIVATE EPS BEARER CONTEXT ACCEPT (step 7) deletes the bearer
//!    contexts, and once every bearer is done answers the Serving GW with the
//!    Delete Bearer Response, Request accepted (step 8).
//!
//! The Delete Bearer Response waits for the UE's DEACTIVATE EPS BEARER CONTEXT
//! ACCEPT (step 7) only; the E-RAB RELEASE RESPONSE (step 5) is diagnosed in
//! `s1ap_handler` and not waited for. That is deliberate: step 8 needs the
//! bearer deactivated in the UE, which only the NAS accept proves, and an eNB
//! that loses its response must not hold the Serving GW (Open5GS keys on the
//! NAS accept too).
//!
//! Lock order: [`PENDING`] is taken before any context pool lock and never
//! under one ([`settle`] takes pool write locks while holding it; no path takes
//! `PENDING` while holding a pool lock).
//!
//! An ECM-IDLE UE whose last PDN connection is not being deleted is handled by
//! condition (i) of §5.4.4.1: steps 4-7 are skipped and the bearer state is
//! synchronised at the next transition to ECM-CONNECTED. With cause
//! "reactivation requested" the procedure would page first (step 4b); that is
//! filed as its own issue.

use std::net::SocketAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::context::MmeContext;

/// T3495 (TS 24.301 Table 10.3.2): 8 s.
pub const T3495_DURATION: Duration = Duration::from_secs(8);
/// Retransmissions before the fifth expiry deactivates locally (§6.4.4.5 a).
const T3495_RETRANSMISSIONS: u32 = 4;

/// What the Delete Bearer Response names (TS 29.274 Table 7.2.10.2-1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeleteBearerAnswer {
    /// The PDN connection, by its Linked EBI.
    Lbi(u8),
    /// The dedicated bearers.
    Ebis(Vec<u8>),
}

/// One bearer waiting for its DEACTIVATE EPS BEARER CONTEXT ACCEPT.
#[derive(Debug, Clone)]
struct Waiting {
    ebi: u8,
    /// The protected ESM message, for T3495 retransmission.
    pkbuf: Vec<u8>,
    retries: u32,
    deadline: Instant,
}

/// A Delete Bearer Request whose answer waits for the UE.
#[derive(Debug, Clone)]
pub struct PendingDeactivation {
    pub mme_ue_id: u64,
    pub peer: SocketAddr,
    pub seq: u32,
    pub sgw_teid: u32,
    pub answer: DeleteBearerAnswer,
    /// The PDN connection being deleted whole (the LBI case).
    sess_id: Option<u64>,
    waiting: Vec<Waiting>,
}

/// The deactivations waiting for the UE. Process-global like the S11 pending
/// maps; tests hold `gtp_path::S11_TEST_LOCK`.
static PENDING: Mutex<Vec<PendingDeactivation>> = Mutex::new(Vec::new());

fn pending() -> std::sync::MutexGuard<'static, Vec<PendingDeactivation>> {
    PENDING.lock().unwrap_or_else(|e| e.into_inner())
}

/// Number of deactivations waiting. Test/diagnostic.
pub fn pending_count() -> usize {
    pending().len()
}

/// Whether a Delete Bearer Request from `peer` at `seq` is already being
/// deactivated: a retransmission is not acted on twice (TS 29.274 §7.6).
pub fn in_flight(peer: SocketAddr, seq: u32) -> bool {
    pending().iter().any(|p| p.peer == peer && p.seq == seq)
}

/// Start deactivating `ebis` of `mme_ue_id` towards the eNB and the UE.
/// `sess_id` is set when the whole PDN connection goes (then `ebis` is its
/// default bearer). `reactivation` selects ESM cause #39 instead of #36.
/// Returns `false` when nothing could be sent (no S1 connection, or every
/// send failed): the caller then deletes locally and answers at once.
#[allow(clippy::too_many_arguments)]
pub fn start(
    ctx: &MmeContext,
    mme_ue_id: u64,
    peer: SocketAddr,
    seq: u32,
    sgw_teid: u32,
    answer: DeleteBearerAnswer,
    sess_id: Option<u64>,
    ebis: &[u8],
    reactivation: bool,
) -> bool {
    let Some(mme_ue) = ctx.mme_ue_find_by_id(mme_ue_id) else {
        return false;
    };
    let Some(enb_ue) = Some(mme_ue.enb_ue_id)
        .filter(|id| *id != crate::context::NEXTGCORE_INVALID_POOL_ID)
        .and_then(|id| ctx.enb_ue_find_by_id(id))
        .filter(|e| e.mme_ue_id == mme_ue_id)
    else {
        return false;
    };
    let cause = if reactivation {
        crate::esm_build::EsmCause::ReactivationRequested
    } else {
        crate::esm_build::EsmCause::RegularDeactivation
    };
    // The E-RABs the eNB is told to release with each NAS message: the whole
    // PDN connection for its default bearer, else the one dedicated bearer.
    let pdn_erabs: Vec<u8> = sess_id
        .and_then(|id| ctx.sess_find_by_id(id))
        .map(|sess| {
            sess.bearer_list
                .iter()
                .filter_map(|b| ctx.bearer_find_by_id(*b))
                .filter(|b| b.enb_s1u_teid != 0)
                .map(|b| b.ebi)
                .collect()
        })
        .unwrap_or_default();
    // The UE-AMBR without this PDN connection (TS 23.401 §4.7.3).
    let ue_ambr = sess_id.and_then(|id| {
        let remaining: Vec<u64> = mme_ue
            .sess_list
            .iter()
            .copied()
            .filter(|s| *s != id)
            .collect();
        let mut probe = mme_ue.clone();
        probe.sess_list = remaining;
        ue_ambr_of(ctx, &probe)
    });
    let mut waiting = Vec::new();
    for ebi in ebis {
        let plain = crate::esm_build::build_deactivate_bearer_context_request_with_params(
            *ebi,
            crate::esm_build::PTI_UNASSIGNED,
            cause,
        );
        let Ok(esm) = crate::nas_path::protect_esm(ctx, mme_ue_id, &plain) else {
            log::error!(
                "[{}] DEACTIVATE EPS BEARER CONTEXT REQUEST for EBI {ebi} not protected; the \
                 bearer is deactivated locally",
                mme_ue.imsi_bcd
            );
            // #863 review: answered accepted with the others, so it must go.
            delete_locally(ctx, mme_ue_id, *ebi, sess_id);
            continue;
        };
        let erabs = if sess_id.is_some() && !pdn_erabs.is_empty() {
            pdn_erabs.clone()
        } else {
            vec![*ebi]
        };
        let cmd = nextgcore_s1ap::ErabReleaseCommand {
            mme_ue_s1ap_id: enb_ue.mme_ue_s1ap_id,
            enb_ue_s1ap_id: enb_ue.enb_ue_s1ap_id,
            ue_ambr,
            erab_list: erabs
                .iter()
                .map(|erab_id| nextgcore_s1ap::ErabItem {
                    erab_id: *erab_id,
                    cause: nextgcore_s1ap::Cause::Nas(nextgcore_s1ap::CauseNas::NormalRelease),
                })
                .collect(),
            nas_pdu: Some(esm.clone()),
        };
        match crate::s1ap_gen::build_erab_release_command(&cmd) {
            Ok(pdu) => {
                crate::s1ap_path::s1ap_send(crate::s1ap_handler::S1apSend {
                    enb_id: enb_ue.enb_id,
                    pdu,
                });
            }
            Err(e) => {
                log::error!(
                    "[{}] E-RAB Release Command for EBI {ebi} not built: {e}; the bearer is \
                     deactivated locally",
                    mme_ue.imsi_bcd
                );
                delete_locally(ctx, mme_ue_id, *ebi, sess_id);
                continue;
            }
        }
        waiting.push(Waiting {
            ebi: *ebi,
            pkbuf: esm,
            retries: 0,
            deadline: Instant::now() + T3495_DURATION,
        });
    }
    if waiting.is_empty() {
        return false;
    }
    log::info!(
        "[{}] Delete Bearer Request: E-RAB RELEASE COMMAND with DEACTIVATE EPS BEARER CONTEXT \
         REQUEST for EBIs {:?}, T3495 armed; the Delete Bearer Response waits (TS 23.401 \
         §5.4.4.1 steps 4c-8)",
        mme_ue.imsi_bcd,
        waiting.iter().map(|w| w.ebi).collect::<Vec<_>>()
    );
    pending().push(PendingDeactivation {
        mme_ue_id,
        peer,
        seq,
        sgw_teid,
        answer,
        sess_id,
        waiting,
    });
    true
}

fn ue_ambr_of(ctx: &MmeContext, ue: &crate::context::MmeUe) -> Option<nextgcore_s1ap::UeAmbr> {
    let (mut dl, mut ul) = (0u64, 0u64);
    for sess in ue
        .sess_list
        .iter()
        .filter_map(|id| ctx.sess_find_by_id(*id))
    {
        dl = dl.saturating_add(sess.ambr.downlink);
        ul = ul.saturating_add(sess.ambr.uplink);
    }
    let cap = |sum: u64, sub: u64| match (sum, sub) {
        (0, s) | (s, 0) => s,
        (s, sub) => s.min(sub),
    };
    let ambr = nextgcore_s1ap::UeAmbr {
        dl: cap(dl, ue.ambr.downlink),
        ul: cap(ul, ue.ambr.uplink),
    };
    (ambr.dl != 0 || ambr.ul != 0).then_some(ambr)
}

/// Delete, in the MME, the bearer `ebi` of `mme_ue_id`, or the whole PDN
/// connection `sess_id`.
fn delete_locally(ctx: &MmeContext, mme_ue_id: u64, ebi: u8, sess_id: Option<u64>) {
    if let Some(sess_id) = sess_id {
        if let Some(sess) = ctx.sess_find_by_id(sess_id) {
            for b in &sess.bearer_list {
                ctx.bearer_remove(*b);
            }
        }
        ctx.sess_remove(sess_id);
        if let Some(ue) = ctx.mme_ue_pool.write().unwrap().get_mut(&mme_ue_id) {
            ue.sess_list.retain(|id| *id != sess_id);
        }
        return;
    }
    let Some(bearer_id) = ctx.bearer_find_by_ebi(mme_ue_id, ebi) else {
        return;
    };
    if let Some(bearer) = ctx.bearer_find_by_id(bearer_id) {
        if let Some(sess) = ctx.sess_pool.write().unwrap().get_mut(&bearer.sess_id) {
            sess.bearer_list.retain(|id| *id != bearer_id);
        }
    }
    ctx.bearer_remove(bearer_id);
}

/// Delete `ebis` (or the PDN connection `sess_id`) of `mme_ue_id` in the MME
/// at once, when the deactivation cannot be signalled.
pub fn delete_now(ctx: &MmeContext, mme_ue_id: u64, ebis: &[u8], sess_id: Option<u64>) {
    for ebi in ebis {
        delete_locally(ctx, mme_ue_id, *ebi, sess_id);
    }
}

/// Answer the Serving GW for a completed deactivation (step 8).
fn answer(p: &PendingDeactivation) {
    use crate::s11_build::GtpCause;
    let rsp = match &p.answer {
        DeleteBearerAnswer::Lbi(lbi) => crate::s11_build::build_delete_bearer_response_for_lbi(
            p.sgw_teid,
            *lbi,
            GtpCause::RequestAccepted,
            p.seq,
        ),
        DeleteBearerAnswer::Ebis(ebis) => crate::s11_build::build_delete_bearer_response_for_ebis(
            p.sgw_teid,
            ebis,
            GtpCause::RequestAccepted,
            p.seq,
        ),
    };
    match rsp {
        Ok(rsp) => {
            if let Err(e) = crate::gtp_path::send_response_to_sgwc(p.peer, &rsp) {
                log::error!("S11 Delete Bearer Response to {} failed: {e}", p.peer);
            }
        }
        Err(e) => log::error!("Delete Bearer Response build failed: {e}"),
    }
}

/// Settle bearer `ebi` of `mme_ue_id`: delete it locally, and answer the
/// Serving GW when it was the last one its request waited for.
fn settle(ctx: &MmeContext, mme_ue_id: u64, ebi: u8, why: &str) -> bool {
    let done = {
        let mut list = pending();
        let Some(i) = list
            .iter()
            .position(|p| p.mme_ue_id == mme_ue_id && p.waiting.iter().any(|w| w.ebi == ebi))
        else {
            return false;
        };
        let p = &mut list[i];
        p.waiting.retain(|w| w.ebi != ebi);
        let sess_id = p.sess_id;
        delete_locally(ctx, mme_ue_id, ebi, sess_id);
        log::info!("UE {mme_ue_id}: EPS bearer {ebi} deactivated ({why})");
        if p.waiting.is_empty() {
            Some(list.remove(i))
        } else {
            None
        }
    };
    if let Some(p) = done {
        answer(&p);
    }
    true
}

/// The PDN connections of `mme_ue_id` a deactivation is deleting whole.
pub fn pending_pdn_sessions(mme_ue_id: u64) -> Vec<u64> {
    pending()
        .iter()
        .filter(|p| p.mme_ue_id == mme_ue_id)
        .filter_map(|p| p.sess_id)
        .collect()
}

/// Whether bearer `ebi` of `mme_ue_id` is already being deactivated: it is
/// waited for, or it belongs to a PDN connection being deleted whole.
pub fn already_deactivating(ctx: &MmeContext, mme_ue_id: u64, ebi: u8) -> bool {
    let list = pending();
    list.iter().filter(|p| p.mme_ue_id == mme_ue_id).any(|p| {
        p.waiting.iter().any(|w| w.ebi == ebi)
            || p.sess_id.is_some_and(|sess_id| {
                ctx.sess_find_by_id(sess_id).is_some_and(|sess| {
                    sess.bearer_list
                        .iter()
                        .filter_map(|b| ctx.bearer_find_by_id(*b))
                        .any(|b| b.ebi == ebi)
                })
            })
    })
}

/// Settle every deactivation of `mme_ue_id` at once (the UE is being
/// detached): its bearers are deleted locally and each request answered.
pub fn settle_all_for_ue(ctx: &MmeContext, mme_ue_id: u64, why: &str) {
    let ebis: Vec<u8> = pending()
        .iter()
        .filter(|p| p.mme_ue_id == mme_ue_id)
        .flat_map(|p| p.waiting.iter().map(|w| w.ebi))
        .collect();
    for ebi in ebis {
        settle(ctx, mme_ue_id, ebi, why);
    }
}

/// DEACTIVATE EPS BEARER CONTEXT ACCEPT for `ebi` (TS 23.401 §5.4.4.1 step 7,
/// TS 24.301 §6.4.4.3). Returns whether it answered a deactivation this module
/// started.
pub fn on_accept(ctx: &MmeContext, mme_ue_id: u64, ebi: u8) -> bool {
    settle(ctx, mme_ue_id, ebi, "DEACTIVATE EPS BEARER CONTEXT ACCEPT")
}

/// Drive T3495 (TS 24.301 §6.4.4.5): retransmit on expiry, and on the fifth
/// expiry, or when the UE context or its S1 connection is gone (§6.4.4.5 b),
/// deactivate locally and answer the Serving GW.
pub fn sweep(ctx: &MmeContext, now: Instant) {
    // The pending deactivations belong to the process-wide context; a unit
    // test's own context must not settle them.
    if !std::ptr::eq(ctx, crate::context::mme_self()) {
        return;
    }
    let mut settle_now: Vec<(u64, u8, &'static str)> = Vec::new();
    let mut resend: Vec<(u64, Vec<u8>)> = Vec::new();
    {
        let mut list = pending();
        for p in list.iter_mut() {
            let connected = ctx.mme_ue_find_by_id(p.mme_ue_id).is_some_and(|ue| {
                ctx.enb_ue_find_by_id(ue.enb_ue_id)
                    .is_some_and(|e| e.mme_ue_id == p.mme_ue_id)
            });
            for w in p.waiting.iter_mut() {
                if !connected {
                    settle_now.push((p.mme_ue_id, w.ebi, "no S1 connection, deactivated locally"));
                } else if now >= w.deadline {
                    if w.retries >= T3495_RETRANSMISSIONS {
                        settle_now.push((
                            p.mme_ue_id,
                            w.ebi,
                            "fifth T3495 expiry, deactivated locally",
                        ));
                    } else {
                        w.retries += 1;
                        w.deadline = now + T3495_DURATION;
                        resend.push((p.mme_ue_id, w.pkbuf.clone()));
                    }
                }
            }
        }
    }
    for (mme_ue_id, pkbuf) in resend {
        let Some(enb_ue) = ctx
            .mme_ue_find_by_id(mme_ue_id)
            .and_then(|ue| ctx.enb_ue_find_by_id(ue.enb_ue_id))
        else {
            continue;
        };
        log::info!("UE {mme_ue_id}: T3495 expired; DEACTIVATE EPS BEARER CONTEXT REQUEST resent");
        if let Err(e) = crate::nas_path::nas_eps_send_to_downlink_nas_transport(&enb_ue, pkbuf) {
            log::error!("UE {mme_ue_id}: T3495 retransmission failed: {e}");
        }
    }
    for (mme_ue_id, ebi, why) in settle_now {
        settle(ctx, mme_ue_id, ebi, why);
    }
}

/// Force every T3495 of `mme_ue_id` to have expired. Test-only.
#[cfg(test)]
pub(crate) fn expire_for_test(mme_ue_id: u64) {
    for p in pending().iter_mut().filter(|p| p.mme_ue_id == mme_ue_id) {
        for w in p.waiting.iter_mut() {
            w.deadline = Instant::now() - Duration::from_millis(1);
        }
    }
}

/// Drop every pending deactivation. Test-only.
#[cfg(test)]
pub(crate) fn clear_for_test() {
    pending().clear();
}
