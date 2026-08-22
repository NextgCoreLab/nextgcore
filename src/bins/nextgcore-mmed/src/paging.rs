//! S1AP Paging (issue #47, TS 36.413 §8.5 / TS 23.401 §5.3.4.3).
//!
//! ## Why this module exists
//!
//! `s1ap_build::build_paging` was complete and had **no callers**: nothing ever
//! paged a UE. `MmeUe::t3413` — the paging retransmission timer — had zero readers
//! and zero writers. And the two events that must trigger paging both had parsers
//! and no action: `s11_handler::handle_downlink_data_notification` (the SGW says
//! downlink data arrived for an idle UE) and `sgsap_handler::handle_paging_request`
//! (the VLR wants the UE for a CS call or SMS). So an idle UE could never be
//! reached: downlink data and terminating calls were dropped silently.
//!
//! ## Fan-out
//!
//! TS 36.413 §8.5.1: the MME sends PAGING to every eNB that serves a tracking area
//! in the UE's TAI list. This selects eNBs by intersecting the UE's last known TAI
//! against each eNB's `supported_ta_list` — the list its S1 SETUP REQUEST
//! advertised — so a UE is paged where it might plausibly be, not everywhere.

use crate::context::{MmeContext, MmeUe, PagingType};
use crate::s1ap_build;
use crate::s1ap_path;
use nextgcore_s1ap::CnDomain;

/// Page a UE for `paging_type`, returning how many eNBs were sent a PAGING.
///
/// Zero means no eNB serves the UE's tracking area, which is reported rather than
/// treated as success: the UE cannot be reached and whatever triggered the paging
/// needs to know.
pub fn page_ue(ctx: &MmeContext, mme_ue_id: u64, paging_type: PagingType) -> usize {
    let Some(mme_ue) = ctx.mme_ue_find_by_id(mme_ue_id) else {
        log::warn!("Paging skipped: UE {mme_ue_id} is gone");
        return 0;
    };

    let cn_domain = cn_domain_for(paging_type);
    let tai_list = vec![mme_ue.tai.clone()];
    let pdu = match s1ap_build::build_paging(&mme_ue, cn_domain, &tai_list, None) {
        Ok(pdu) => pdu,
        Err(e) => {
            log::error!("[{}] failed to build Paging: {e}", mme_ue.imsi_bcd);
            return 0;
        }
    };

    let targets = enbs_serving(ctx, &mme_ue);
    if targets.is_empty() {
        log::warn!(
            "[{}] no eNB serves TAC {}; the UE cannot be paged",
            mme_ue.imsi_bcd,
            mme_ue.tai.tac
        );
        return 0;
    }

    for enb_id in &targets {
        s1ap_path::s1ap_send_pdu(*enb_id, pdu.clone());
    }

    // Arm T3413 with the message, so the sweep can retransmit it: the UE may be
    // asleep and miss the first page (TS 24.301 §5.6.2.2).
    if let Some(mme_ue) = ctx.mme_ue_pool.write().unwrap().get_mut(&mme_ue_id) {
        mme_ue.paging.type_ = paging_type;
        mme_ue.paging.failed = false;
        mme_ue.t3413.pkbuf = Some(pdu);
        mme_ue.t3413.start(crate::nas_timer::T3413_DURATION);
    }

    log::info!(
        "[{}] paged on {} eNB(s) for {paging_type:?}",
        mme_ue.imsi_bcd,
        targets.len()
    );
    targets.len()
}

/// Stop paging: the UE answered, or the procedure was abandoned.
pub fn stop_paging(ctx: &MmeContext, mme_ue_id: u64) {
    if let Some(mme_ue) = ctx.mme_ue_pool.write().unwrap().get_mut(&mme_ue_id) {
        if mme_ue.t3413.is_running() {
            log::debug!("[{}] paging answered; T3413 stopped", mme_ue.imsi_bcd);
        }
        mme_ue.t3413.stop();
        mme_ue.paging.type_ = PagingType::None;
    }
}

/// eNB pool ids whose advertised tracking areas include the UE's.
///
/// An eNB that completed S1 Setup without advertising any TA is excluded: there is
/// no evidence it serves this UE, and paging every eNB would leak the UE's identity
/// across the whole network.
fn enbs_serving(ctx: &MmeContext, mme_ue: &MmeUe) -> Vec<u64> {
    ctx.enb_pool
        .read()
        .unwrap()
        .iter()
        .filter(|(_, enb)| {
            enb.state.s1_setup_success && enb.supported_ta_list.contains(&mme_ue.tai)
        })
        .map(|(id, _)| *id)
        .collect()
}

/// CN domain the paging is on behalf of (TS 36.413 §9.2.3.22).
fn cn_domain_for(paging_type: PagingType) -> CnDomain {
    match paging_type {
        // A CS call or an SMS over SGs is the circuit-switched domain asking.
        PagingType::CsCallService | PagingType::SmsService => CnDomain::Cs,
        _ => CnDomain::Ps,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::{EpsTai, PlmnId};

    fn ctx_with_enb_serving(tac: u16) -> (MmeContext, u64) {
        let ctx = MmeContext::new();
        ctx.init();
        let enb_id = ctx.enb_add("127.0.0.1:36412".parse().unwrap());
        if let Some(enb) = ctx.enb_pool.write().unwrap().get_mut(&enb_id) {
            enb.state.s1_setup_success = true;
            enb.supported_ta_list = vec![EpsTai {
                plmn_id: PlmnId::new("310", "410"),
                tac,
            }];
        }
        (ctx, enb_id)
    }

    fn idle_ue(ctx: &MmeContext, tac: u16) -> u64 {
        let mme_ue_id = ctx.mme_ue_add(crate::context::NEXTGCORE_INVALID_POOL_ID);
        ctx.mme_ue_set_imsi(mme_ue_id, "310410123456789");
        if let Some(mme_ue) = ctx.mme_ue_pool.write().unwrap().get_mut(&mme_ue_id) {
            mme_ue.tai = EpsTai {
                plmn_id: PlmnId::new("310", "410"),
                tac,
            };
        }
        mme_ue_id
    }

    #[test]
    fn test_pages_the_enb_serving_the_ues_tracking_area() {
        let (ctx, _) = ctx_with_enb_serving(7);
        let mme_ue_id = idle_ue(&ctx, 7);

        assert_eq!(
            page_ue(&ctx, mme_ue_id, PagingType::DownlinkDataNotification),
            1
        );

        let mme_ue = ctx.mme_ue_find_by_id(mme_ue_id).unwrap();
        assert_eq!(mme_ue.paging.type_, PagingType::DownlinkDataNotification);
        assert!(!mme_ue.paging.failed);
        assert!(mme_ue.t3413.is_running(), "T3413 must be armed");
        assert!(mme_ue.t3413.pkbuf.is_some(), "the PAGING is kept to resend");
    }

    #[test]
    fn test_an_enb_in_another_tracking_area_is_not_paged() {
        let (ctx, _) = ctx_with_enb_serving(7);
        let mme_ue_id = idle_ue(&ctx, 99);

        assert_eq!(
            page_ue(&ctx, mme_ue_id, PagingType::DownlinkDataNotification),
            0,
            "paging every eNB would leak the UE identity network-wide"
        );
        assert!(!ctx.mme_ue_find_by_id(mme_ue_id).unwrap().t3413.is_running());
    }

    #[test]
    fn test_an_enb_without_a_completed_setup_is_not_paged() {
        let (ctx, enb_id) = ctx_with_enb_serving(7);
        if let Some(enb) = ctx.enb_pool.write().unwrap().get_mut(&enb_id) {
            enb.state.s1_setup_success = false;
        }
        let mme_ue_id = idle_ue(&ctx, 7);

        assert_eq!(page_ue(&ctx, mme_ue_id, PagingType::SmsService), 0);
    }

    #[test]
    fn test_stop_paging_clears_the_timer_and_the_type() {
        let (ctx, _) = ctx_with_enb_serving(7);
        let mme_ue_id = idle_ue(&ctx, 7);
        page_ue(&ctx, mme_ue_id, PagingType::CsCallService);

        stop_paging(&ctx, mme_ue_id);

        let mme_ue = ctx.mme_ue_find_by_id(mme_ue_id).unwrap();
        assert!(!mme_ue.t3413.is_running());
        assert!(mme_ue.t3413.pkbuf.is_none());
        assert_eq!(mme_ue.paging.type_, PagingType::None);
    }

    #[test]
    fn test_cn_domain_follows_the_trigger() {
        assert_eq!(cn_domain_for(PagingType::CsCallService), CnDomain::Cs);
        assert_eq!(cn_domain_for(PagingType::SmsService), CnDomain::Cs);
        assert_eq!(
            cn_domain_for(PagingType::DownlinkDataNotification),
            CnDomain::Ps
        );
    }
}
