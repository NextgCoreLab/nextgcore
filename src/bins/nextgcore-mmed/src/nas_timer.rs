//! NAS procedure timers (issue #45, TS 24.301 §5.4/§5.5).
//!
//! ## Why this module exists
//!
//! `TimerWithRetry` held a retransmission buffer and a retry counter that
//! nothing read or wrote, and there was no deadline field anywhere: the
//! T3450/T3460/T3470 branches in `sm.rs` only logged. So a lost downlink NAS
//! message left the procedure outstanding forever — no retransmission, no abort,
//! no context release, and the stored `pkbuf` never discarded.
//!
//! ## Model
//!
//! Deadlines live on the UE context beside the buffer they would resend (see
//! [`crate::context::TimerWithRetry`]), and [`expire_nas_timers`] sweeps the UE
//! pool. `MmeApp::run` already wakes every 100 ms to check the shutdown flag, so
//! the sweep rides that tick: no extra task, no channel, and — unlike amfd's
//! `TimerManager`, which can start and stop timers but has no expiry function at
//! all — it cannot silently stop firing. Tick granularity is irrelevant against
//! six-second NAS timers.
//!
//! ## Retransmission
//!
//! TS 24.301 §5.4.2.7 b) (T3460), §5.4.4.6 (T3470) and §5.5.1.2.7 (T3450) all use
//! the same wording: the message is retransmitted on each expiry, "repeated four
//! times, i.e. on the fifth expiry … the network shall abort the procedure" and
//! release the NAS signalling connection. So four retransmissions, five expiries.

use std::time::{Duration, Instant};

use crate::context::MmeEpsType;
use crate::context::{EnbUe, MmeContext, MmeUe, NEXTGCORE_INVALID_POOL_ID};
use crate::nas_path;

/// T3450 — ATTACH ACCEPT / TAU ACCEPT (TS 24.301 Table 10.2.1).
pub const T3450_DURATION: Duration = Duration::from_secs(6);

/// T3460 — AUTHENTICATION REQUEST and SECURITY MODE COMMAND.
pub const T3460_DURATION: Duration = Duration::from_secs(6);

/// T3470 — IDENTITY REQUEST.
pub const T3470_DURATION: Duration = Duration::from_secs(6);

/// T3413 — PAGING.
///
/// TS 24.301 Table 10.2.1 leaves the value to the network; 6 s matches the other
/// NAS retransmission timers and gives a sleeping UE a DRX cycle or two to answer.
pub const T3413_DURATION: Duration = Duration::from_secs(6);

/// T3422 — DETACH REQUEST from the network (TS 24.301 Table 10.2.1, §5.5.2.3.1).
pub const T3422_DURATION: Duration = Duration::from_secs(6);

/// Retransmissions before the procedure is aborted on the next expiry.
pub const MAX_RETRANSMISSIONS: u32 = 4;

/// Which NAS timer expired.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NasTimer {
    /// Attach / TAU accept
    T3450,
    /// Authentication request or security mode command
    T3460,
    /// Identity request
    T3470,
    /// Paging
    T3413,
    /// Network-initiated detach (#688)
    T3422,
}

impl NasTimer {
    /// The timer's configured duration.
    pub fn duration(self) -> Duration {
        match self {
            NasTimer::T3450 => T3450_DURATION,
            NasTimer::T3460 => T3460_DURATION,
            NasTimer::T3470 => T3470_DURATION,
            NasTimer::T3413 => T3413_DURATION,
            NasTimer::T3422 => T3422_DURATION,
        }
    }

    fn name(self) -> &'static str {
        match self {
            NasTimer::T3450 => "T3450",
            NasTimer::T3460 => "T3460",
            NasTimer::T3470 => "T3470",
            NasTimer::T3413 => "T3413",
            NasTimer::T3422 => "T3422",
        }
    }

    fn on(self, mme_ue: &mut MmeUe) -> &mut crate::context::TimerWithRetry {
        match self {
            NasTimer::T3450 => &mut mme_ue.t3450,
            NasTimer::T3460 => &mut mme_ue.t3460,
            NasTimer::T3470 => &mut mme_ue.t3470,
            NasTimer::T3413 => &mut mme_ue.t3413,
            NasTimer::T3422 => &mut mme_ue.t3422,
        }
    }
}

const ALL_TIMERS: [NasTimer; 5] = [
    NasTimer::T3450,
    NasTimer::T3460,
    NasTimer::T3470,
    NasTimer::T3413,
    NasTimer::T3422,
];

/// Retransmit or abort every NAS procedure whose timer has expired by `now`.
///
/// Expiries are collected under a read lock and acted on afterwards, so the
/// retransmission path can take the write lock and reach `nas_path` without the
/// non-reentrant `RwLock` deadlocking against itself.
pub fn expire_nas_timers(ctx: &MmeContext, now: Instant) {
    // #734: T3495 of the PDN GW initiated bearer deactivations.
    crate::bearer_deactivation::sweep(ctx, now);
    // #641: T3485 of the network-initiated dedicated bearer activations.
    crate::bearer_activation::sweep(ctx, now);
    // #641: T3486 of the network-initiated bearer modifications.
    crate::bearer_modification::sweep(ctx, now);
    let expired: Vec<(u64, NasTimer)> = {
        let pool = ctx.mme_ue_pool.read().unwrap();
        pool.iter()
            .flat_map(|(id, mme_ue)| {
                ALL_TIMERS.into_iter().filter_map(move |timer| {
                    let state = match timer {
                        NasTimer::T3450 => &mme_ue.t3450,
                        NasTimer::T3460 => &mme_ue.t3460,
                        NasTimer::T3470 => &mme_ue.t3470,
                        NasTimer::T3413 => &mme_ue.t3413,
                        NasTimer::T3422 => &mme_ue.t3422,
                    };
                    state.is_expired(now).then_some((*id, timer))
                })
            })
            .collect()
    };

    for (mme_ue_id, timer) in expired {
        handle_expiry(ctx, mme_ue_id, timer);
    }
}

fn handle_expiry(ctx: &MmeContext, mme_ue_id: u64, timer: NasTimer) {
    // #956: paging is for a UE with NO S1 connection, so T3413 cannot go
    // through the S1-connection check below (which aborted it at its first
    // expiry, so paging was never repeated): it repages on every eNB serving
    // the UE's tracking area.
    if timer == NasTimer::T3413 {
        paging_expiry(ctx, mme_ue_id);
        return;
    }
    let enb_ue = ctx
        .mme_ue_find_by_id(mme_ue_id)
        .map(|mme_ue| mme_ue.enb_ue_id)
        .filter(|id| *id != NEXTGCORE_INVALID_POOL_ID)
        .and_then(|id| ctx.enb_ue_find_by_id(id));

    // Retransmission needs a live S1 connection. Without one there is nothing to
    // resend over, so the procedure is aborted immediately rather than counting
    // down against a UE that is already unreachable.
    let Some(enb_ue) = enb_ue else {
        let imsi = {
            let mut pool = ctx.mme_ue_pool.write().unwrap();
            let Some(mme_ue) = pool.get_mut(&mme_ue_id) else {
                return;
            };
            timer.on(mme_ue).stop();
            mme_ue.imsi_bcd.clone()
        };
        log::warn!(
            "[{imsi}] {} expired with no S1 connection; procedure aborted",
            timer.name()
        );
        // TS 24.301 §5.5.2.3.4 b: an aborted network detach still leaves the UE
        // EMM-DEREGISTERED in the network, including one another procedure overtook
        // (#828, as the with-S1 branch below).
        if timer == NasTimer::T3422 {
            crate::network_detach::abandon_mme_initiated_detach(ctx, mme_ue_id);
        }
        return;
    };

    let abort = {
        let mut pool = ctx.mme_ue_pool.write().unwrap();
        let Some(mme_ue) = pool.get_mut(&mme_ue_id) else {
            return;
        };

        // #732: T3422 supervises the network-initiated detach only while that
        // detach is the UE's procedure. An ATTACH that aborted it (TS 24.301
        // §5.5.2.3.5 d) stops the timer; this catches any path that did not, so
        // a stale DETACH REQUEST is never resent and a re-attaching UE is never
        // released by the fifth expiry.
        if timer == NasTimer::T3422 && mme_ue.nas_eps.type_ != MmeEpsType::DetachRequestToUe {
            timer.on(mme_ue).stop();
            if mme_ue.network_detach_type.is_none() {
                // The detach was aborted (an ATTACH, §5.5.2.3.5 d): nothing to do.
                log::info!(
                    "[{}] T3422 expired, but no network-initiated detach is in progress; stopped",
                    mme_ue.imsi_bcd
                );
                return;
            }
            // #828: the detach was never aborted, yet another procedure took the
            // UE's EMM state. Its bearers are already gone, so leaving it would
            // keep a registered UE with no PDN connection that is never told.
            // The detach is completed: EMM-DEREGISTERED (§5.5.2.3.5 a).
            log::warn!(
                "[{}] T3422 expired with the network-initiated detach overtaken by {:?}; \
                 completing the detach (TS 24.301 §5.5.2.3.5 a)",
                mme_ue.imsi_bcd,
                mme_ue.nas_eps.type_
            );
            drop(pool);
            ctx.mme_ue_remove(mme_ue_id);
            crate::nas_dispatch::release_ue_context(ctx, &enb_ue);
            return;
        }

        let state = timer.on(mme_ue);
        // Re-check under the write lock against a fresh instant: an uplink
        // message may have stopped or re-armed this timer between the sweep's
        // read and this point.
        if !state.is_expired(Instant::now()) {
            return;
        }

        if state.retry_count >= MAX_RETRANSMISSIONS {
            state.stop();
            true
        } else {
            let pkbuf = state.pkbuf.clone();
            state.record_retransmission(timer.duration());
            let attempt = state.retry_count;
            match pkbuf {
                Some(pkbuf) => {
                    log::info!(
                        "[{}] {} expired; retransmission {attempt}/{MAX_RETRANSMISSIONS}",
                        mme_ue.imsi_bcd,
                        timer.name()
                    );
                    retransmit(mme_ue, &enb_ue, timer, pkbuf);
                    false
                }
                None => {
                    // Armed with nothing to resend: treat it as an abort rather
                    // than spinning for four more rounds.
                    log::warn!(
                        "[{}] {} expired with no stored message; procedure aborted",
                        mme_ue.imsi_bcd,
                        timer.name()
                    );
                    timer.on(mme_ue).stop();
                    true
                }
            }
        }
    };

    if abort && timer == NasTimer::T3422 {
        // TS 24.301 §5.5.2.3.4 b: "on the fifth expiry of timer T3422, the detach
        // procedure shall be aborted and the MME enters state EMM-DEREGISTERED".
        log::warn!(
            "T3422 exhausted its {MAX_RETRANSMISSIONS} retransmissions for UE {mme_ue_id}; \
             detaching it locally and releasing the S1 connection"
        );
        // Only a detach that is still the procedure releases: the UE may have
        // started another one in the meantime (#732).
        if crate::network_detach::complete_mme_initiated_detach(ctx, mme_ue_id) {
            crate::nas_dispatch::release_ue_context(ctx, &enb_ue);
        }
        return;
    }

    if abort {
        // TS 24.301 §5.4.2.7 / §5.4.4.6 / §5.5.1.2.7: after the last
        // retransmission the network aborts the procedure and releases the NAS
        // signalling connection.
        log::warn!(
            "{} exhausted its {MAX_RETRANSMISSIONS} retransmissions for UE {mme_ue_id}; \
             releasing the S1 connection",
            timer.name()
        );
        crate::nas_dispatch::release_ue_context(ctx, &enb_ue);
    }
}

/// T3413 expired (TS 24.301 §5.6.2.2.1, TS 23.401 §5.3.4.3): the PAGING is
/// repeated up to [`MAX_RETRANSMISSIONS`] times on every eNB serving the UE,
/// then the paging fails and whatever triggered it is told (#956: a Downlink
/// Data Notification gets its Failure Indication, cause UE not responding).
fn paging_expiry(ctx: &MmeContext, mme_ue_id: u64) {
    let action = {
        let mut pool = ctx.mme_ue_pool.write().unwrap();
        let Some(mme_ue) = pool.get_mut(&mme_ue_id) else {
            return;
        };
        if !mme_ue.t3413.is_expired(Instant::now()) {
            return;
        }
        if mme_ue.t3413.retry_count >= MAX_RETRANSMISSIONS || mme_ue.t3413.pkbuf.is_none() {
            mme_ue.t3413.stop();
            let paging_type = mme_ue.paging.type_;
            mme_ue.paging.failed = true;
            mme_ue.paging.type_ = crate::context::PagingType::None;
            log::warn!(
                "[{}] paging gave up: the UE did not respond ({paging_type:?})",
                mme_ue.imsi_bcd
            );
            Err(paging_type)
        } else {
            let pdu = mme_ue.t3413.pkbuf.clone().unwrap_or_default();
            mme_ue.t3413.record_retransmission(T3413_DURATION);
            log::info!(
                "[{}] T3413 expired; paging repeated ({}/{MAX_RETRANSMISSIONS})",
                mme_ue.imsi_bcd,
                mme_ue.t3413.retry_count
            );
            Ok(pdu)
        }
    };
    match action {
        Ok(pdu) => {
            crate::paging::repeat(ctx, mme_ue_id, pdu);
        }
        Err(paging_type) => {
            if paging_type == crate::context::PagingType::DownlinkDataNotification {
                if let Err(e) = crate::gtp_path::send_downlink_data_notification_failure_indication(
                    ctx,
                    mme_ue_id,
                    crate::s11_build::GtpCause::UeNotResponding,
                ) {
                    log::error!(
                        "UE {mme_ue_id}: Downlink Data Notification Failure Indication not sent: {e}"
                    );
                }
            }
            // #862: deactivations waiting for this paging complete locally.
            crate::bearer_deactivation::on_paging_failed(ctx, mme_ue_id);
            // #641: activations waiting for this paging are refused.
            crate::bearer_activation::on_paging_failed(ctx, mme_ue_id);
            crate::bearer_modification::on_paging_failed(ctx, mme_ue_id);
        }
    }
}

fn retransmit(mme_ue: &MmeUe, enb_ue: &EnbUe, timer: NasTimer, pkbuf: Vec<u8>) {
    if timer == NasTimer::T3413 {
        // T3413 holds a complete S1AP PAGING PDU, which is NOT UE-associated and
        // must not be wrapped in DOWNLINK NAS TRANSPORT: it goes to the eNB as it
        // is (TS 36.413 §8.5).
        crate::s1ap_path::s1ap_send_pdu(enb_ue.enb_id, pkbuf);
        return;
    }
    // The stored buffer is the complete NAS message the procedure sent, already
    // security-encoded where the procedure applied protection, so it is resent
    // verbatim inside a fresh DOWNLINK NAS TRANSPORT.
    if let Err(e) = nas_path::nas_eps_send_to_downlink_nas_transport(enb_ue, pkbuf) {
        log::error!(
            "[{}] {} retransmission failed: {e}",
            mme_ue.imsi_bcd,
            timer.name()
        );
    }
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::emm_build::NasEpsMessageType;

    /// A UE with a live S1 connection and an outstanding IDENTITY REQUEST.
    fn ue_with_outstanding_identity_request(ctx: &MmeContext) -> (u64, u64) {
        let enb_id = ctx.enb_add("127.0.0.1:36412".parse().unwrap());
        let enb_ue_id = ctx.enb_ue_add(enb_id, 100);
        let mme_ue_id = ctx.mme_ue_add(enb_ue_id);
        ctx.enb_ue_associate_mme_ue(enb_ue_id, mme_ue_id);
        {
            let mut pool = ctx.mme_ue_pool.write().unwrap();
            let mme_ue = pool.get_mut(&mme_ue_id).unwrap();
            mme_ue.t3470.pkbuf = Some(vec![0x07, NasEpsMessageType::IdentityRequest as u8, 0x01]);
            mme_ue.t3470.start(T3470_DURATION);
        }
        (enb_ue_id, mme_ue_id)
    }

    /// Move a timer's deadline into the past instead of sleeping.
    fn force_expiry(ctx: &MmeContext, mme_ue_id: u64, timer: NasTimer) {
        let mut pool = ctx.mme_ue_pool.write().unwrap();
        let mme_ue = pool.get_mut(&mme_ue_id).unwrap();
        timer.on(mme_ue).expires_at = Instant::now().checked_sub(Duration::from_secs(1));
    }

    fn test_ctx() -> MmeContext {
        let ctx = MmeContext::new();
        ctx.init();
        ctx
    }

    /// #688: T3422 retransmits the DETACH REQUEST, and on the fifth expiry
    /// the UE is detached locally (TS 24.301 §5.5.2.3.4 b).
    #[test]
    fn test_t3422_retransmits_then_detaches_locally() {
        let ctx = test_ctx();
        let enb_id = ctx.enb_add("127.0.0.1:36412".parse().unwrap());
        let enb_ue_id = ctx.enb_ue_add(enb_id, 100);
        let mme_ue_id = ctx.mme_ue_add(enb_ue_id);
        ctx.enb_ue_associate_mme_ue(enb_ue_id, mme_ue_id);
        crate::network_detach::mme_initiated_detach(
            &ctx,
            mme_ue_id,
            crate::emm_build::DetachTypeToUe::ReAttachRequired,
            "test",
        );
        for n in 1..=MAX_RETRANSMISSIONS {
            force_expiry(&ctx, mme_ue_id, NasTimer::T3422);
            expire_nas_timers(&ctx, Instant::now());
            let ue = ctx.mme_ue_find_by_id(mme_ue_id).expect("still detaching");
            assert_eq!(ue.t3422.retry_count, n);
        }
        force_expiry(&ctx, mme_ue_id, NasTimer::T3422);
        expire_nas_timers(&ctx, Instant::now());
        assert!(ctx.mme_ue_find_by_id(mme_ue_id).is_none());
    }

    /// #732: once the detach is no longer the UE's procedure, T3422 neither
    /// resends the stale DETACH REQUEST nor, on its fifth expiry, releases the
    /// UE. Before #732 the fifth expiry released a re-attaching UE.
    #[test]
    fn t3422_is_inert_once_the_detach_is_not_the_procedure() {
        let ctx = test_ctx();
        let enb_id = ctx.enb_add("127.0.0.1:36412".parse().unwrap());
        let enb_ue_id = ctx.enb_ue_add(enb_id, 100);
        let mme_ue_id = ctx.mme_ue_add(enb_ue_id);
        ctx.enb_ue_associate_mme_ue(enb_ue_id, mme_ue_id);
        crate::network_detach::mme_initiated_detach(
            &ctx,
            mme_ue_id,
            crate::emm_build::DetachTypeToUe::ReAttachRequired,
            "test",
        );
        // An ATTACH aborted the detach (§5.5.2.3.5 d) but, on some path, left
        // the timer armed.
        {
            let mut pool = ctx.mme_ue_pool.write().unwrap();
            let ue = pool.get_mut(&mme_ue_id).unwrap();
            ue.nas_eps.type_ = MmeEpsType::AttachRequest;
            ue.network_detach_type = None;
        }
        force_expiry(&ctx, mme_ue_id, NasTimer::T3422);
        expire_nas_timers(&ctx, Instant::now());
        let ue = ctx.mme_ue_find_by_id(mme_ue_id).unwrap();
        assert_eq!(
            ue.t3422.retry_count, 0,
            "the stale DETACH REQUEST is not resent"
        );
        assert!(!ue.t3422.is_running(), "T3422 stopped at its first expiry");
        for _ in 0..MAX_RETRANSMISSIONS {
            force_expiry(&ctx, mme_ue_id, NasTimer::T3422);
            expire_nas_timers(&ctx, Instant::now());
        }
        let ue = ctx
            .mme_ue_find_by_id(mme_ue_id)
            .expect("the UE is not released");
        assert_eq!(ue.t3422.retry_count, 0, "nothing was retransmitted");
        assert!(!ue.t3422.is_running());
        assert!(
            ctx.enb_ue_find_by_id(enb_ue_id).is_some(),
            "S1 not released"
        );
    }

    /// #828: a detach that was never aborted but whose EMM state another
    /// procedure took (a CS fallback ESR before #828 routed it) is completed at
    /// the next T3422 expiry: the bearer-less UE is deregistered and S1
    /// released, not left registered and never told.
    #[test]
    fn t3422_completes_a_detach_another_procedure_overtook() {
        let ctx = test_ctx();
        let enb_id = ctx.enb_add("127.0.0.1:36412".parse().unwrap());
        let enb_ue_id = ctx.enb_ue_add(enb_id, 100);
        let mme_ue_id = ctx.mme_ue_add(enb_ue_id);
        ctx.enb_ue_associate_mme_ue(enb_ue_id, mme_ue_id);
        crate::network_detach::mme_initiated_detach(
            &ctx,
            mme_ue_id,
            crate::emm_build::DetachTypeToUe::ReAttachRequired,
            "test",
        );
        ctx.mme_ue_pool
            .write()
            .unwrap()
            .get_mut(&mme_ue_id)
            .unwrap()
            .nas_eps
            .type_ = MmeEpsType::ExtendedServiceRequest;
        force_expiry(&ctx, mme_ue_id, NasTimer::T3422);
        expire_nas_timers(&ctx, Instant::now());
        assert!(
            ctx.mme_ue_find_by_id(mme_ue_id).is_none(),
            "the detach is completed: EMM-DEREGISTERED"
        );
    }

    /// #828 follow-up: the overtaken-detach rule holds when T3422 expires with no S1
    /// connection too. The detach is completed (the bearer-less UE deregistered), while a
    /// detach an ATTACH aborted is left alone in the same branch.
    #[test]
    fn t3422_without_s1_completes_an_overtaken_detach_and_spares_an_aborted_one() {
        for (aborted, expect_removed) in [(false, true), (true, false)] {
            let ctx = test_ctx();
            let enb_id = ctx.enb_add("127.0.0.1:36412".parse().unwrap());
            let enb_ue_id = ctx.enb_ue_add(enb_id, 100);
            let mme_ue_id = ctx.mme_ue_add(enb_ue_id);
            ctx.enb_ue_associate_mme_ue(enb_ue_id, mme_ue_id);
            crate::network_detach::mme_initiated_detach(
                &ctx,
                mme_ue_id,
                crate::emm_build::DetachTypeToUe::ReAttachRequired,
                "test",
            );
            {
                let mut pool = ctx.mme_ue_pool.write().unwrap();
                let ue = pool.get_mut(&mme_ue_id).unwrap();
                ue.nas_eps.type_ = if aborted {
                    MmeEpsType::AttachRequest
                } else {
                    MmeEpsType::ExtendedServiceRequest
                };
                if aborted {
                    ue.network_detach_type = None;
                }
                // The S1 connection is gone.
                ue.enb_ue_id = NEXTGCORE_INVALID_POOL_ID;
            }
            force_expiry(&ctx, mme_ue_id, NasTimer::T3422);
            expire_nas_timers(&ctx, Instant::now());
            assert_eq!(
                ctx.mme_ue_find_by_id(mme_ue_id).is_none(),
                expect_removed,
                "aborted={aborted}"
            );
        }
    }

    #[test]
    fn test_a_running_timer_is_left_alone() {
        let ctx = test_ctx();
        let (_, mme_ue_id) = ue_with_outstanding_identity_request(&ctx);

        expire_nas_timers(&ctx, Instant::now());

        let mme_ue = ctx.mme_ue_find_by_id(mme_ue_id).unwrap();
        assert_eq!(mme_ue.t3470.retry_count, 0);
        assert!(mme_ue.t3470.is_running());
    }

    #[test]
    fn test_expiry_retransmits_and_counts() {
        let ctx = test_ctx();
        let (_, mme_ue_id) = ue_with_outstanding_identity_request(&ctx);

        for expected in 1..=MAX_RETRANSMISSIONS {
            force_expiry(&ctx, mme_ue_id, NasTimer::T3470);
            expire_nas_timers(&ctx, Instant::now());

            let mme_ue = ctx.mme_ue_find_by_id(mme_ue_id).unwrap();
            assert_eq!(
                mme_ue.t3470.retry_count, expected,
                "each expiry must retransmit once and re-arm"
            );
            assert!(mme_ue.t3470.is_running());
            assert!(
                mme_ue.t3470.pkbuf.is_some(),
                "the message must be kept for the next retransmission"
            );
        }
    }

    #[test]
    fn test_the_fifth_expiry_aborts_and_releases_the_connection() {
        let ctx = test_ctx();
        let (enb_ue_id, mme_ue_id) = ue_with_outstanding_identity_request(&ctx);

        for _ in 0..MAX_RETRANSMISSIONS {
            force_expiry(&ctx, mme_ue_id, NasTimer::T3470);
            expire_nas_timers(&ctx, Instant::now());
        }
        // The fifth expiry: TS 24.301 §5.4.4.6 aborts instead of retransmitting.
        force_expiry(&ctx, mme_ue_id, NasTimer::T3470);
        expire_nas_timers(&ctx, Instant::now());

        let mme_ue = ctx.mme_ue_find_by_id(mme_ue_id).unwrap();
        assert!(!mme_ue.t3470.is_running(), "the timer must be stopped");
        assert!(mme_ue.t3470.pkbuf.is_none());
        assert_eq!(mme_ue.t3470.retry_count, 0);
        assert_eq!(
            ctx.enb_ue_find_by_id(enb_ue_id).unwrap().ue_ctx_rel_action,
            crate::context::UeCtxRelAction::UeContextRemove,
            "the S1 connection must be released"
        );
    }

    #[test]
    fn test_t3413_retransmits_the_paging_then_gives_up() {
        let ctx = test_ctx();
        let enb_id = ctx.enb_add("127.0.0.1:36412".parse().unwrap());
        let enb_ue_id = ctx.enb_ue_add(enb_id, 100);
        let mme_ue_id = ctx.mme_ue_add(enb_ue_id);
        ctx.enb_ue_associate_mme_ue(enb_ue_id, mme_ue_id);
        {
            let mut pool = ctx.mme_ue_pool.write().unwrap();
            let mme_ue = pool.get_mut(&mme_ue_id).unwrap();
            // A complete S1AP PAGING PDU stands in as the stored message.
            mme_ue.t3413.pkbuf = Some(vec![0x00, 0x0a, 0x40, 0x01]);
            mme_ue.t3413.start(T3413_DURATION);
            mme_ue.paging.type_ = crate::context::PagingType::DownlinkDataNotification;
        }

        for expected in 1..=MAX_RETRANSMISSIONS {
            force_expiry(&ctx, mme_ue_id, NasTimer::T3413);
            expire_nas_timers(&ctx, Instant::now());
            assert_eq!(
                ctx.mme_ue_find_by_id(mme_ue_id).unwrap().t3413.retry_count,
                expected
            );
        }

        force_expiry(&ctx, mme_ue_id, NasTimer::T3413);
        expire_nas_timers(&ctx, Instant::now());

        let mme_ue = ctx.mme_ue_find_by_id(mme_ue_id).unwrap();
        assert!(!mme_ue.t3413.is_running());
        assert!(
            mme_ue.paging.failed,
            "TS 23.401 §5.3.4.3: the trigger needs to know the UE never answered"
        );
        assert_eq!(mme_ue.paging.type_, crate::context::PagingType::None);
        // Paging has no NAS signalling connection, so giving up must NOT release
        // one -- the S1 context (if any) is untouched.
        assert!(ctx.enb_ue_find_by_id(enb_ue_id).is_some());
    }

    #[test]
    fn test_a_stopped_timer_never_expires() {
        let ctx = test_ctx();
        let (_, mme_ue_id) = ue_with_outstanding_identity_request(&ctx);
        {
            // What the completing message does.
            let mut pool = ctx.mme_ue_pool.write().unwrap();
            pool.get_mut(&mme_ue_id).unwrap().t3470.stop();
        }

        expire_nas_timers(&ctx, Instant::now() + Duration::from_secs(3600));

        let mme_ue = ctx.mme_ue_find_by_id(mme_ue_id).unwrap();
        assert_eq!(mme_ue.t3470.retry_count, 0);
        assert!(!mme_ue.t3470.is_running());
        assert!(mme_ue.t3470.pkbuf.is_none());
    }

    #[test]
    fn test_expiry_without_an_s1_connection_aborts_immediately() {
        let ctx = test_ctx();
        let (enb_ue_id, mme_ue_id) = ue_with_outstanding_identity_request(&ctx);
        ctx.enb_ue_deassociate_mme_ue(enb_ue_id, mme_ue_id);

        force_expiry(&ctx, mme_ue_id, NasTimer::T3470);
        expire_nas_timers(&ctx, Instant::now());

        let mme_ue = ctx.mme_ue_find_by_id(mme_ue_id).unwrap();
        assert!(!mme_ue.t3470.is_running());
        assert_eq!(mme_ue.t3470.retry_count, 0);
    }

    #[test]
    fn test_each_timer_is_swept_independently() {
        let ctx = test_ctx();
        let (_, mme_ue_id) = ue_with_outstanding_identity_request(&ctx);
        {
            let mut pool = ctx.mme_ue_pool.write().unwrap();
            let mme_ue = pool.get_mut(&mme_ue_id).unwrap();
            mme_ue.t3460.pkbuf = Some(vec![0x07, NasEpsMessageType::AuthenticationRequest as u8]);
            mme_ue.t3460.start(T3460_DURATION);
        }

        force_expiry(&ctx, mme_ue_id, NasTimer::T3460);
        expire_nas_timers(&ctx, Instant::now());

        let mme_ue = ctx.mme_ue_find_by_id(mme_ue_id).unwrap();
        assert_eq!(mme_ue.t3460.retry_count, 1);
        assert_eq!(
            mme_ue.t3470.retry_count, 0,
            "an unexpired timer on the same UE must not be touched"
        );
    }
}
