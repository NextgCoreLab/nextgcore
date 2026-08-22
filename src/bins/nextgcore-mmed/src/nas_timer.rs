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
}

impl NasTimer {
    /// The timer's configured duration.
    pub fn duration(self) -> Duration {
        match self {
            NasTimer::T3450 => T3450_DURATION,
            NasTimer::T3460 => T3460_DURATION,
            NasTimer::T3470 => T3470_DURATION,
            NasTimer::T3413 => T3413_DURATION,
        }
    }

    fn name(self) -> &'static str {
        match self {
            NasTimer::T3450 => "T3450",
            NasTimer::T3460 => "T3460",
            NasTimer::T3470 => "T3470",
            NasTimer::T3413 => "T3413",
        }
    }

    fn on(self, mme_ue: &mut MmeUe) -> &mut crate::context::TimerWithRetry {
        match self {
            NasTimer::T3450 => &mut mme_ue.t3450,
            NasTimer::T3460 => &mut mme_ue.t3460,
            NasTimer::T3470 => &mut mme_ue.t3470,
            NasTimer::T3413 => &mut mme_ue.t3413,
        }
    }
}

const ALL_TIMERS: [NasTimer; 4] = [
    NasTimer::T3450,
    NasTimer::T3460,
    NasTimer::T3470,
    NasTimer::T3413,
];

/// Retransmit or abort every NAS procedure whose timer has expired by `now`.
///
/// Expiries are collected under a read lock and acted on afterwards, so the
/// retransmission path can take the write lock and reach `nas_path` without the
/// non-reentrant `RwLock` deadlocking against itself.
pub fn expire_nas_timers(ctx: &MmeContext, now: Instant) {
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
        return;
    };

    let abort = {
        let mut pool = ctx.mme_ue_pool.write().unwrap();
        let Some(mme_ue) = pool.get_mut(&mme_ue_id) else {
            return;
        };

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

    if abort && timer == NasTimer::T3413 {
        // A paging procedure has no NAS signalling connection to release -- that
        // is the point of paging. TS 23.401 §5.3.4.3: the UE did not respond, so
        // the procedure is marked failed and whatever triggered it decides
        // (buffer, drop, or report).
        if let Some(mme_ue) = ctx.mme_ue_pool.write().unwrap().get_mut(&mme_ue_id) {
            mme_ue.paging.failed = true;
            mme_ue.paging.type_ = crate::context::PagingType::None;
            log::warn!(
                "[{}] paging gave up: the UE did not respond",
                mme_ue.imsi_bcd
            );
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
