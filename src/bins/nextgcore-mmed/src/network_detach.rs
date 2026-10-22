//! The MME-initiated detach (TS 23.401 §5.3.8.3, TS 24.301 §5.5.2.3), for a UE
//! whose PDN connections the core has lost.
//!
//! # Why it exists
//!
//! The one way an MME can make an attached UE come back after its user plane is
//! gone is a DETACH REQUEST with detach type "re-attach required". Before #688
//! nothing sent one for that reason. A PGW-initiated Delete Bearer Request for the
//! default bearer was logged as "not implemented" and left unanswered. A
//! restarted SGW was logged (#689). Either way the UE kept a default bearer that
//! no gateway held, and never got service back.
//!
//! # What it does
//!
//! [`mme_initiated_detach`]:
//! 1. deletes the UE's EPS bearer and PDN connection contexts locally. The
//!    gateway side is already gone in both callers: the PGW deleted it (#688), or
//!    the SGW restarted (#689). So no Delete Session Request is sent;
//! 2. when the UE is ECM-CONNECTED, sends DETACH REQUEST on its S1 connection
//!    and arms T3422 (§5.5.2.3.1). DETACH ACCEPT, or the fifth T3422 expiry
//!    (§5.5.2.3.4 b), then removes the UE context and releases the S1
//!    connection (`nas_dispatch`, `nas_timer`);
//! 3. when the UE is ECM-IDLE, detaches it implicitly (§5.5.2.3.1 allows a local
//!    detach instead of paging). The UE's next SERVICE REQUEST or TAU then
//!    meets a context-less MME and is rejected #9/#10, which also re-attaches it.
//!
//! The UE context is removed rather than kept without bearers. The re-attach
//! that follows carries the old S-TMSI, and `resolve_mme_ue` would otherwise
//! hand it the old context with every flag of the old attach still set.

use crate::context::{MmeContext, MmeEpsType, NEXTGCORE_INVALID_POOL_ID};
use crate::emm_build::DetachTypeToUe;

/// What [`mme_initiated_detach`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetachOutcome {
    /// DETACH REQUEST sent on the UE's S1 connection; T3422 is running.
    DetachRequestSent,
    /// The UE had no S1 connection (or the request could not be sent): its
    /// context was removed (implicit detach).
    ImplicitlyDetached,
    /// No such UE context.
    NoContext,
}

/// Remove every PDN connection and EPS bearer context of `mme_ue_id`, locally.
/// Returns the number of PDN connections removed.
pub fn delete_pdn_connections_locally(ctx: &MmeContext, mme_ue_id: u64) -> usize {
    if let Some(ue) = ctx.mme_ue_pool.write().unwrap().get_mut(&mme_ue_id) {
        ue.sess_list.clear();
    }
    // By owner rather than through the parent links, so a context whose links
    // were never completed (a rejected request) cannot leave orphans behind.
    ctx.bearer_pool
        .write()
        .unwrap()
        .retain(|_, b| b.mme_ue_id != mme_ue_id);
    let mut sessions = ctx.sess_pool.write().unwrap();
    let before = sessions.len();
    sessions.retain(|_, s| s.mme_ue_id != mme_ue_id);
    before - sessions.len()
}

/// Detach `mme_ue_id` from the network side because `reason`, with
/// `detach_type` (TS 24.301 §5.5.2.3.1).
pub fn mme_initiated_detach(
    ctx: &MmeContext,
    mme_ue_id: u64,
    detach_type: DetachTypeToUe,
    reason: &str,
) -> DetachOutcome {
    let Some(mme_ue) = ctx.mme_ue_find_by_id(mme_ue_id) else {
        return DetachOutcome::NoContext;
    };
    let imsi = mme_ue.imsi_bcd.clone();
    let deleted = delete_pdn_connections_locally(ctx, mme_ue_id);

    let enb_ue = Some(mme_ue.enb_ue_id)
        .filter(|id| *id != NEXTGCORE_INVALID_POOL_ID)
        .and_then(|id| ctx.enb_ue_find_by_id(id))
        .filter(|enb_ue| enb_ue.mme_ue_id == mme_ue_id);

    if let Some(enb_ue) = enb_ue {
        let mut pool = ctx.mme_ue_pool.write().unwrap();
        if let Some(ue) = pool.get_mut(&mme_ue_id) {
            ue.nas_eps.type_ = MmeEpsType::DetachRequestToUe;
            // A fresh procedure: a stale buffer would be resent instead.
            ue.t3422.stop();
            match crate::nas_path::nas_eps_send_detach_request(ue, &enb_ue, detach_type) {
                Ok(()) => {
                    ue.t3422.start(crate::nas_timer::T3422_DURATION);
                    log::warn!(
                        "[{imsi}] MME-initiated detach ({detach_type:?}) after {reason}: \
                         {deleted} PDN connection(s) deleted locally; DETACH REQUEST sent, \
                         T3422 armed (TS 24.301 §5.5.2.3.1)"
                    );
                    return DetachOutcome::DetachRequestSent;
                }
                Err(e) => log::error!(
                    "[{imsi}] DETACH REQUEST after {reason} could not be sent ({e:?}); \
                     detaching implicitly"
                ),
            }
        }
        drop(pool);
        ctx.mme_ue_remove(mme_ue_id);
        crate::nas_dispatch::release_ue_context(ctx, &enb_ue);
        return DetachOutcome::ImplicitlyDetached;
    }

    log::warn!(
        "[{imsi}] implicit detach after {reason}: the UE is ECM-IDLE, {deleted} PDN \
         connection(s) deleted and the UE context removed (TS 24.301 §5.5.2.3.1); its next \
         SERVICE REQUEST or TAU is rejected and it re-attaches"
    );
    ctx.mme_ue_remove(mme_ue_id);
    DetachOutcome::ImplicitlyDetached
}

/// The network side of a completed MME-initiated detach: DETACH ACCEPT arrived,
/// or T3422 gave up (§5.5.2.3.2, §5.5.2.3.4 b). Returns whether `mme_ue_id`
/// was in one, in which case its context is gone and the caller releases S1.
pub fn complete_mme_initiated_detach(ctx: &MmeContext, mme_ue_id: u64) -> bool {
    let in_detach = ctx
        .mme_ue_find_by_id(mme_ue_id)
        .is_some_and(|ue| ue.nas_eps.type_ == MmeEpsType::DetachRequestToUe);
    if in_detach {
        ctx.mme_ue_remove(mme_ue_id);
    }
    in_detach
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::emm_build::NasEpsMessageType;

    pub(crate) fn test_ctx() -> MmeContext {
        let ctx = MmeContext::new();
        ctx.init();
        ctx
    }

    /// An attached UE: S1 connection, IMSI, one PDN connection whose default
    /// bearer is EBI 5.
    pub(crate) fn attached_ue(ctx: &MmeContext, connected: bool) -> (u64, u64, u64) {
        let enb_id = ctx.enb_add("127.0.0.1:36412".parse().unwrap());
        let enb_ue_id = ctx.enb_ue_add(enb_id, 100);
        let mme_ue_id = ctx.mme_ue_add(enb_ue_id);
        if connected {
            ctx.enb_ue_associate_mme_ue(enb_ue_id, mme_ue_id);
        } else if let Some(ue) = ctx.mme_ue_pool.write().unwrap().get_mut(&mme_ue_id) {
            ue.enb_ue_id = NEXTGCORE_INVALID_POOL_ID;
        }
        ctx.mme_ue_set_imsi(mme_ue_id, "999700000000001");
        let sess_id = ctx.sess_add(mme_ue_id, 1);
        let bearer_id = ctx.bearer_add(sess_id, mme_ue_id);
        if let Some(b) = ctx.bearer_pool.write().unwrap().get_mut(&bearer_id) {
            b.ebi = 5;
        }
        if let Some(s) = ctx.sess_pool.write().unwrap().get_mut(&sess_id) {
            s.bearer_list.push(bearer_id);
        }
        if let Some(ue) = ctx.mme_ue_pool.write().unwrap().get_mut(&mme_ue_id) {
            ue.sess_list.push(sess_id);
        }
        (enb_ue_id, mme_ue_id, sess_id)
    }

    #[test]
    fn a_connected_ue_is_sent_detach_request_re_attach_required() {
        let ctx = test_ctx();
        let (enb_ue_id, mme_ue_id, sess_id) = attached_ue(&ctx, true);

        let out = mme_initiated_detach(&ctx, mme_ue_id, DetachTypeToUe::ReAttachRequired, "t");

        assert_eq!(out, DetachOutcome::DetachRequestSent);
        let ue = ctx
            .mme_ue_find_by_id(mme_ue_id)
            .expect("kept until DETACH ACCEPT");
        assert!(ue.sess_list.is_empty(), "PDN connections deleted");
        assert!(ctx.sess_find_by_id(sess_id).is_none());
        assert!(ctx.bearer_find_by_ebi(mme_ue_id, 5).is_none());
        assert!(ue.t3422.is_running(), "T3422 armed");
        let nas = ue.t3422.pkbuf.expect("DETACH REQUEST stored for T3422");
        // No NAS algorithms in this test context, so the plain message is the tail.
        let plain = &nas[nas.len() - 5..];
        assert_eq!(
            plain,
            &[
                0x07,
                NasEpsMessageType::DetachRequest as u8,
                0x01,
                0x53,
                0x0a
            ],
            "DETACH REQUEST, detach type 1 (re-attach required)"
        );
        assert_eq!(ue.nas_eps.type_, MmeEpsType::DetachRequestToUe);

        // DETACH ACCEPT completes it: the context goes.
        assert!(complete_mme_initiated_detach(&ctx, mme_ue_id));
        assert!(ctx.mme_ue_find_by_id(mme_ue_id).is_none());
        let _ = enb_ue_id;
    }

    #[test]
    fn re_attach_not_required_carries_no_cause() {
        let ctx = test_ctx();
        let (_, mme_ue_id, _) = attached_ue(&ctx, true);
        mme_initiated_detach(&ctx, mme_ue_id, DetachTypeToUe::ReAttachNotRequired, "t");
        let nas = ctx
            .mme_ue_find_by_id(mme_ue_id)
            .unwrap()
            .t3422
            .pkbuf
            .unwrap();
        assert_eq!(
            &nas[nas.len() - 3..],
            &[0x07, NasEpsMessageType::DetachRequest as u8, 0x02]
        );
    }

    #[test]
    fn an_idle_ue_is_detached_implicitly() {
        let ctx = test_ctx();
        let (_, mme_ue_id, sess_id) = attached_ue(&ctx, false);

        let out = mme_initiated_detach(&ctx, mme_ue_id, DetachTypeToUe::ReAttachRequired, "t");

        assert_eq!(out, DetachOutcome::ImplicitlyDetached);
        assert!(ctx.mme_ue_find_by_id(mme_ue_id).is_none());
        assert!(ctx.mme_ue_find_by_imsi("999700000000001").is_none());
        assert!(ctx.sess_find_by_id(sess_id).is_none());
    }

    #[test]
    fn a_detach_accept_outside_an_mme_initiated_detach_keeps_the_context() {
        let ctx = test_ctx();
        let (_, mme_ue_id, _) = attached_ue(&ctx, true);
        assert!(!complete_mme_initiated_detach(&ctx, mme_ue_id));
        assert!(ctx.mme_ue_find_by_id(mme_ue_id).is_some());
    }
}
