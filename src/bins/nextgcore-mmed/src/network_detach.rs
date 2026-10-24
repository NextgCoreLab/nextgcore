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
//! 1. deletes the UE's EPS bearer and PDN connection contexts locally. For the
//!    PGW-deleted PDN (#688) and the SGW restart (#689) the gateway side is
//!    already gone, so no Delete Session Request is sent. The HSS-initiated
//!    detach (CLR, #733, TS 23.401 §5.3.8.4) sends one per PDN connection
//!    first, through `gtp_path::send_delete_all_sessions`, then calls this;
//! 2. when the UE is ECM-CONNECTED, sends DETACH REQUEST on its S1 connection
//!    and arms T3422 (§5.5.2.3.1). DETACH ACCEPT, or the fifth T3422 expiry
//!    (§5.5.2.3.5 a), then removes the UE context and releases the S1
//!    connection (`nas_dispatch`, `nas_timer`). An ATTACH, TAU or SERVICE
//!    REQUEST meanwhile is handled by [`on_colliding_procedure`] (#732);
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
    let sgw_ue_id = {
        let mut pool = ctx.mme_ue_pool.write().unwrap();
        pool.get_mut(&mme_ue_id).map(|ue| {
            ue.sess_list.clear();
            ue.sgw_ue_id
        })
    };
    // #828: with every PDN connection gone the Serving GW holds no S11 context
    // for the UE, so its TEID must not head the next Create Session Request
    // (TS 29.274 §5.5.2: an initial request to a new context carries TEID 0).
    if let Some(sgw_ue_id) = sgw_ue_id {
        if let Some(sgw_ue) = ctx.sgw_ue_pool.write().unwrap().get_mut(&sgw_ue_id) {
            sgw_ue.sgw_s11_teid = 0;
        }
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
            ue.network_detach_type = Some(detach_type);
            // Whoever started this detach marks it; a CLR does so after this returns.
            ue.network_detach_by_clr = false;
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

/// A UE-initiated EMM procedure that can collide with a network-initiated
/// detach (TS 24.301 §5.5.2.3.5 d-f).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CollidingProcedure {
    /// ATTACH REQUEST (case d).
    Attach,
    /// TRACKING AREA UPDATE REQUEST (case e).
    TrackingAreaUpdate,
    /// SERVICE REQUEST, or EXTENDED SERVICE REQUEST for packet services (case f).
    ServiceRequest,
    /// EXTENDED SERVICE REQUEST for CS fallback (service type 0-4, TS 24.301
    /// Table 9.9.3.27.1). Case f defines it only for IMSI detach and cause #2;
    /// for the detach types this MME sends, the detach is progressed (#828).
    CsFallbackServiceRequest,
}

/// What to do with a UE-initiated procedure that arrives while a network-initiated
/// detach is pending.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Collision {
    /// No detach is pending, or the detach was aborted: process the message.
    Proceed,
    /// The detach is progressed: the message is ignored.
    Ignore,
}

/// TS 24.301 §5.5.2.3.5 d-f (#732), for the detach types this MME sends
/// ("re-attach required", "re-attach not required" without EMM cause #2; and
/// "IMSI detach" for completeness):
/// - ATTACH REQUEST: re-attach required, the detach is aborted (T3422 stopped)
///   and the attach progressed; the EPS bearer contexts were already deleted by
///   [`mme_initiated_detach`]. Re-attach not required: the ATTACH is ignored.
///   IMSI detach: aborted, attach progressed.
/// - TAU REQUEST: ignored, the detach progressed (IMSI detach: aborted, TAU
///   progressed).
/// - SERVICE REQUEST: the detach is progressed, so the request is ignored (IMSI
///   detach: both progress).
///
/// Before #732 every one of them overwrote `nas_eps.type_` and left T3422
/// running, so its fifth expiry released a UE that was re-attaching.
pub fn on_colliding_procedure(
    ctx: &MmeContext,
    mme_ue_id: u64,
    procedure: CollidingProcedure,
) -> Collision {
    use crate::emm_build::DetachTypeToUe as T;
    let mut pool = ctx.mme_ue_pool.write().unwrap();
    let Some(ue) = pool.get_mut(&mme_ue_id) else {
        return Collision::Proceed;
    };
    if ue.nas_eps.type_ != MmeEpsType::DetachRequestToUe {
        return Collision::Proceed;
    }
    let detach_type = ue.network_detach_type.unwrap_or(T::ReAttachRequired);
    let abort = match (procedure, detach_type) {
        (CollidingProcedure::Attach, T::ReAttachRequired | T::ImsiDetach) => true,
        (CollidingProcedure::Attach, T::ReAttachNotRequired) => false,
        (CollidingProcedure::TrackingAreaUpdate, T::ImsiDetach) => true,
        (CollidingProcedure::TrackingAreaUpdate, _) => false,
        // §5.5.2.3.5 f has both procedures progress for an IMSI detach. This
        // MME never sends one (only re-attach required / not required), and the
        // service request handlers take over the UE's EMM procedure, so the
        // detach is progressed instead: the request is ignored.
        (CollidingProcedure::ServiceRequest | CollidingProcedure::CsFallbackServiceRequest, _) => {
            false
        }
    };
    if abort {
        ue.t3422.stop();
        ue.nas_eps.type_ = MmeEpsType::None;
        ue.network_detach_type = None;
        ue.network_detach_by_clr = false;
        log::info!(
            "[{}] {procedure:?} during a network-initiated detach ({detach_type:?}): the detach \
             is aborted, T3422 stopped, and the {procedure:?} progressed (TS 24.301 \
             §5.5.2.3.5)",
            ue.imsi_bcd
        );
        Collision::Proceed
    } else {
        log::info!(
            "[{}] {procedure:?} during a network-initiated detach ({detach_type:?}): ignored, \
             the detach is progressed (TS 24.301 §5.5.2.3.5)",
            ue.imsi_bcd
        );
        Collision::Ignore
    }
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

/// T3422 ran out with no S1 connection to resend over (TS 24.301 §5.5.2.3.4 b): the detach
/// is abandoned and the UE is EMM-DEREGISTERED in the network. Returns whether the context was
/// removed.
///
/// Unlike [`complete_mme_initiated_detach`] this also covers a detach another procedure
/// overtook without aborting (the `nas_eps.type_` moved on, `network_detach_type` did not
/// clear): the UE's PDN connections were already deleted by [`mme_initiated_detach`], so
/// keeping the context would leave a registered UE with no bearers that is never told (#828,
/// the rule the with-S1 branch of `nas_timer` applies). A detach that was aborted
/// (§5.5.2.3.5 d) cleared `network_detach_type` and is left alone.
pub fn abandon_mme_initiated_detach(ctx: &MmeContext, mme_ue_id: u64) -> bool {
    let detaching = ctx.mme_ue_find_by_id(mme_ue_id).is_some_and(|ue| {
        ue.nas_eps.type_ == MmeEpsType::DetachRequestToUe || ue.network_detach_type.is_some()
    });
    if detaching {
        ctx.mme_ue_remove(mme_ue_id);
    }
    detaching
}

/// TS 23.007 §15 (#689): the Serving GW at `restarted` lost its contexts.
///
/// Every UE with a PDN connection established through it is detached with
/// "re-attach required" (or implicitly, when idle). "Established" means the SGW's
/// S11 TEID is recorded for the UE. A Create Session still in flight to the
/// restarted SGW is not counted: its response comes from the new incarnation and
/// is applied after this runs.
///
/// The MME does not record a per-UE SGW. Every request goes to `sgw_in_use`, the
/// first configured `sgwc` (TS 23.401 §4.3.8.1 selection is not implemented). So
/// a restart of a peer that is not that SGW detaches nobody. Returns the number
/// of UEs detached.
pub fn sgw_restarted(
    ctx: &MmeContext,
    sgw_in_use: Option<std::net::SocketAddr>,
    restarted: std::net::IpAddr,
) -> usize {
    if sgw_in_use.map(|a| a.ip()) != Some(restarted) {
        log::info!(
            "S11 peer {restarted} restarted, but it is not the Serving GW this MME uses \
             ({sgw_in_use:?}); no UE is affected"
        );
        return 0;
    }
    let affected: Vec<u64> = {
        let pool = ctx.mme_ue_pool.read().unwrap();
        pool.iter()
            .filter(|(_, ue)| ue.nas_eps.type_ != MmeEpsType::DetachRequestToUe)
            .filter(|(_, ue)| {
                ctx.sgw_ue_find_by_id(ue.sgw_ue_id)
                    .is_some_and(|s| s.sgw_s11_teid != 0)
            })
            .map(|(id, _)| *id)
            .collect()
    };
    for id in &affected {
        mme_initiated_detach(
            ctx,
            *id,
            DetachTypeToUe::ReAttachRequired,
            &format!("a restart of its Serving GW {restarted} (TS 23.007 §15)"),
        );
    }
    affected.len()
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

    #[test]
    fn a_restart_of_the_sgw_in_use_detaches_its_ues_re_attach_required() {
        let ctx = test_ctx();
        let sgw: std::net::SocketAddr = "10.10.4.41:2123".parse().unwrap();
        let (_, on_sgw, _) = attached_ue(&ctx, true);
        ctx.set_sgw_s11_teid_for_ue(on_sgw, 0x11);
        let (_, idle_on_sgw, _) = attached_ue(&ctx, false);
        ctx.set_sgw_s11_teid_for_ue(idle_on_sgw, 0x12);
        // Mid-attach: a session exists but the SGW has not answered yet.
        let (_, attaching, _) = attached_ue(&ctx, true);

        assert_eq!(sgw_restarted(&ctx, Some(sgw), sgw.ip()), 2);

        let ue = ctx
            .mme_ue_find_by_id(on_sgw)
            .expect("kept until DETACH ACCEPT");
        assert!(ue.sess_list.is_empty());
        assert_eq!(ue.nas_eps.type_, MmeEpsType::DetachRequestToUe);
        let nas = ue.t3422.pkbuf.expect("DETACH REQUEST");
        assert_eq!(&nas[nas.len() - 5..nas.len() - 2], &[0x07, 0x45, 0x01]);
        assert!(
            ctx.mme_ue_find_by_id(idle_on_sgw).is_none(),
            "idle: implicit"
        );
        let ue = ctx.mme_ue_find_by_id(attaching).unwrap();
        assert_eq!(ue.sess_list.len(), 1, "an attach in flight is left alone");

        // A second restart does not re-detach a UE already being detached.
        assert_eq!(sgw_restarted(&ctx, Some(sgw), sgw.ip()), 0);
    }

    #[test]
    fn a_restart_of_another_peer_detaches_nobody() {
        let ctx = test_ctx();
        let (_, id, _) = attached_ue(&ctx, true);
        ctx.set_sgw_s11_teid_for_ue(id, 0x11);
        let sgw: std::net::SocketAddr = "10.10.4.41:2123".parse().unwrap();
        assert_eq!(
            sgw_restarted(&ctx, Some(sgw), "10.10.9.9".parse().unwrap()),
            0
        );
        assert_eq!(sgw_restarted(&ctx, None, sgw.ip()), 0);
        assert_eq!(ctx.mme_ue_find_by_id(id).unwrap().sess_list.len(), 1);
    }
}
