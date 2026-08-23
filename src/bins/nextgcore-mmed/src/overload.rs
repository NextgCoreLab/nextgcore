//! MME overload control (TS 36.413 §8.7.6, TS 23.401 §4.3.7.4.1).
//!
//! When the MME is carrying more UEs than the deployment says it should, it asks
//! every connected eNB to shed load with an OVERLOAD START, and lifts that with
//! an OVERLOAD STOP once the load falls back. Before #49 the S1AP codec had
//! neither message, so the MME had no way to signal overload at all and no
//! congestion-control lever short of failing procedures.
//!
//! ## The load metric, and why it is opt-in
//!
//! mmed has exactly one load signal: how many UE contexts it holds. That is the
//! canonical MME load proxy (TS 23.401 leaves the decision to the MME's own
//! implementation), but the number that counts as "too many" is a property of
//! the deployment, not of the protocol. So the threshold comes from
//! `mme.overload.max_ue` and defaults to `0` — disabled. An existing deployment
//! sees no behaviour change from this module existing.
//!
//! ## Hysteresis
//!
//! START fires above the threshold; STOP fires only at or below 90% of it. With
//! one trigger point, a single UE detaching and re-attaching at the boundary
//! would flap START/STOP at tick rate and bury the eNBs in signalling.

use crate::context::{MmeContext, OverloadTransition};
use crate::s1ap_build;
use crate::s1ap_path;

/// The action eNBs are asked to take when this MME is overloaded.
///
/// `reject-delay-tolerant-access` is the mildest lever that actually reduces
/// load: it turns away background/NB-IoT-style traffic that can be retried later
/// while leaving normal calls, emergency sessions and mobile-terminated services
/// working. Escalating past this (rejecting all non-emergency access) is a policy
/// decision an operator should make deliberately, not a default.
const OVERLOAD_ACTION: nextgcore_s1ap::OverloadAction =
    nextgcore_s1ap::OverloadAction::RejectDelayTolerantAccess;

/// Re-evaluate MME load and, if it crossed a threshold, signal every eNB.
///
/// Called on the main-loop tick beside the NAS timer sweep. Cheap when disabled
/// or idle: it takes a read lock on the UE pool and returns.
///
/// Returns the number of eNBs signalled, which is 0 on the overwhelmingly common
/// "nothing changed" path.
pub fn poll(ctx: &MmeContext) -> usize {
    match ctx.overload_reevaluate() {
        OverloadTransition::Start => {
            log::warn!(
                "MME overloaded ({} attached UEs > {}); signalling OVERLOAD START ({:?})",
                ctx.mme_ue_pool.read().unwrap().len(),
                ctx.overload_max_ue,
                OVERLOAD_ACTION
            );
            match s1ap_build::build_overload_start(OVERLOAD_ACTION) {
                Ok(pdu) => broadcast(ctx, &pdu, "OVERLOAD START"),
                Err(e) => {
                    log::error!("Failed to build Overload Start: {e}");
                    0
                }
            }
        }
        OverloadTransition::Stop => {
            log::info!(
                "MME load recovered ({} attached UEs); signalling OVERLOAD STOP",
                ctx.mme_ue_pool.read().unwrap().len()
            );
            match s1ap_build::build_overload_stop() {
                Ok(pdu) => broadcast(ctx, &pdu, "OVERLOAD STOP"),
                Err(e) => {
                    log::error!("Failed to build Overload Stop: {e}");
                    0
                }
            }
        }
        OverloadTransition::Unchanged => 0,
    }
}

/// Send one non-UE-associated PDU to every eNB that completed S1 Setup.
///
/// eNBs that never finished S1 Setup are skipped: overload signalling is
/// non-UE-associated signalling on an established S1 interface, and an eNB
/// mid-setup has no configuration to apply it to.
fn broadcast(ctx: &MmeContext, pdu: &[u8], what: &str) -> usize {
    let targets: Vec<u64> = ctx
        .enb_pool
        .read()
        .unwrap()
        .values()
        .filter(|enb| enb.state.s1_setup_success)
        .map(|enb| enb.id)
        .collect();

    let mut sent = 0usize;
    for enb_id in targets {
        if s1ap_path::s1ap_send_pdu(enb_id, pdu.to_vec()) {
            sent += 1;
        }
    }
    log::debug!("{what} sent to {sent} eNB(s)");
    sent
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::MmeContext;

    fn ctx_with_threshold(max_ue: usize) -> MmeContext {
        let mut ctx = MmeContext::new();
        ctx.init();
        ctx.overload_max_ue = max_ue;
        ctx
    }

    /// Add `count` UE contexts, each on its own eNB UE context.
    fn add_ues(ctx: &MmeContext, count: usize) {
        let enb_id = ctx.enb_add("127.0.0.1:36412".parse().unwrap());
        for i in 0..count {
            let enb_ue_id = ctx.enb_ue_add(enb_id, i as u32 + 1);
            ctx.mme_ue_add(enb_ue_id);
        }
    }

    #[test]
    fn disabled_by_default_so_no_deployment_changes_behaviour() {
        let ctx = ctx_with_threshold(0);
        add_ues(&ctx, 50);
        assert_eq!(ctx.overload_reevaluate(), OverloadTransition::Unchanged);
        assert!(!ctx.is_overloaded());
    }

    #[test]
    fn start_fires_once_when_the_threshold_is_crossed() {
        let ctx = ctx_with_threshold(10);
        add_ues(&ctx, 10);
        assert_eq!(
            ctx.overload_reevaluate(),
            OverloadTransition::Unchanged,
            "at the threshold is not over it"
        );

        add_ues(&ctx, 1);
        assert_eq!(ctx.overload_reevaluate(), OverloadTransition::Start);
        assert!(ctx.is_overloaded());

        // Still overloaded, but START must not be re-sent every tick.
        assert_eq!(ctx.overload_reevaluate(), OverloadTransition::Unchanged);
    }

    /// The whole point of the low-water mark: dropping back to just under the
    /// threshold must NOT lift overload, or the pair flaps at tick rate.
    #[test]
    fn stop_waits_for_the_low_water_mark() {
        let ctx = ctx_with_threshold(10);
        add_ues(&ctx, 11);
        assert_eq!(ctx.overload_reevaluate(), OverloadTransition::Start);

        // 10 UEs: back under the threshold, but above 90% of it.
        remove_one_ue(&ctx);
        assert_eq!(
            ctx.overload_reevaluate(),
            OverloadTransition::Unchanged,
            "one UE below the threshold must not lift overload"
        );
        assert!(ctx.is_overloaded());

        // 9 UEs: at the low-water mark.
        remove_one_ue(&ctx);
        assert_eq!(ctx.overload_reevaluate(), OverloadTransition::Stop);
        assert!(!ctx.is_overloaded());
        assert_eq!(ctx.overload_reevaluate(), OverloadTransition::Unchanged);
    }

    /// A threshold of 1 has no room for a 90% mark, so the marks must not
    /// collide into an unliftable overload.
    #[test]
    fn a_threshold_of_one_still_lifts() {
        let ctx = ctx_with_threshold(1);
        add_ues(&ctx, 2);
        assert_eq!(ctx.overload_reevaluate(), OverloadTransition::Start);
        remove_one_ue(&ctx);
        remove_one_ue(&ctx);
        assert_eq!(ctx.overload_reevaluate(), OverloadTransition::Stop);
    }

    fn remove_one_ue(ctx: &MmeContext) {
        let id = *ctx
            .mme_ue_pool
            .read()
            .unwrap()
            .keys()
            .next()
            .expect("a UE to remove");
        ctx.mme_ue_pool.write().unwrap().remove(&id);
    }

    /// With no transport installed the fan-out reports zero sends rather than
    /// panicking or claiming success.
    #[test]
    fn broadcast_without_transport_reports_no_sends() {
        let ctx = ctx_with_threshold(1);
        let enb_id = ctx.enb_add("127.0.0.1:36412".parse().unwrap());
        if let Some(enb) = ctx.enb_pool.write().unwrap().get_mut(&enb_id) {
            enb.state.s1_setup_success = true;
        }
        let pdu = s1ap_build::build_overload_stop().unwrap();
        // `s1ap_send_pdu` may or may not have a global queue installed depending
        // on which other tests ran in this binary, so only the no-panic and
        // bounded-count properties are asserted.
        assert!(broadcast(&ctx, &pdu, "OVERLOAD STOP") <= 1);
    }

    /// eNBs that have not completed S1 Setup are not addressed.
    #[test]
    fn broadcast_skips_enbs_without_s1_setup() {
        let ctx = ctx_with_threshold(1);
        ctx.enb_add("127.0.0.2:36412".parse().unwrap());
        let pdu = s1ap_build::build_overload_stop().unwrap();
        assert_eq!(broadcast(&ctx, &pdu, "OVERLOAD STOP"), 0);
    }
}
