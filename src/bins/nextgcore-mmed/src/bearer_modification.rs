//! PDN GW initiated bearer modification towards the eNB and the UE (#641 Update
//! Bearer half, TS 23.401 §5.4.2.1 steps 3-8, TS 24.301 §6.4.3).
//!
//! The Serving GW's Update Bearer Request used to fall into the "not handled" arm: no
//! answer, so the Serving GW and the PGW ran out N3 and the change (a new TFT, a new
//! Bearer QoS, a new APN-AMBR) never reached the eNB or the UE. This module carries it
//! out:
//! 1. **The request** (TS 29.274 Table 7.2.15-1): the APN-AMBR (M), the PTI when the UE
//!    asked, and per Bearer Context the EBI with an optional TFT and Bearer QoS. A
//!    Bearer Context naming no bearer of the UE is answered "Context not found".
//! 2. **Signalling** (step 4), per bearer: MODIFY EPS BEARER CONTEXT REQUEST with the
//!    New EPS QoS, the TFT and the APN-AMBR as they change. With a QoS change it rides
//!    in an E-RAB MODIFY REQUEST, which also carries the new UE-AMBR when the APN-AMBR
//!    change moves it (TS 23.401 §4.7.3, the #869 review); otherwise in DOWNLINK NAS
//!    TRANSPORT, with a UE CONTEXT MODIFICATION REQUEST for a UE-AMBR change. T3486 is
//!    armed (TS 24.301 §6.4.3.2). An ECM-IDLE UE is paged first
//!    (`PagingType::UpdateBearer`, step 3).
//! 3. **The join**: a bearer is modified once its E-RAB MODIFY RESPONSE item (when an
//!    E-RAB MODIFY was sent) and the UE's MODIFY EPS BEARER CONTEXT ACCEPT have arrived.
//!    Only then are the new QoS, TFT and APN-AMBR stored. A REJECT ("UE refuses"), a
//!    failed E-RAB, or the fifth T3486 expiry ("UE not responding") leaves the bearer as
//!    it was.
//! 4. **The answer** (step 8): Update Bearer Response under the request's sequence
//!    number, each bearer with its cause; message cause 16, 17 or the first failure's.
//!
//! Lock order as in `bearer_activation`: [`PENDING`] is never taken under a pool lock.

use std::net::SocketAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use nextgcore_gtp::v2::{Gtp2BearerContextIe, Gtp2CauseIe, Gtp2IeType, Gtp2Message};

use crate::context::{Bitrate, MmeContext, Qos};
use crate::s11_build::GtpCause;

/// T3486 (TS 24.301 Table 10.3.2): 8 s.
pub const T3486_DURATION: Duration = Duration::from_secs(8);
/// Retransmissions before the fifth expiry aborts the procedure (§6.4.3.5).
const T3486_RETRANSMISSIONS: u32 = 4;

#[derive(Debug, Clone)]
struct Item {
    /// 0 when the EBI names no bearer of the UE.
    bearer_id: u64,
    ebi: u8,
    qos: Option<Qos>,
    tft: Option<Vec<u8>>,
    pkbuf: Vec<u8>,
    retries: u32,
    deadline: Instant,
    /// `None` when no E-RAB MODIFY is sent for it (no QoS change).
    erab: Option<Option<Result<(), GtpCause>>>,
    nas: Option<Result<(), GtpCause>>,
    refused: Option<GtpCause>,
}

impl Item {
    fn outcome(&self) -> Option<Result<(), GtpCause>> {
        if let Some(c) = self.refused {
            return Some(Err(c));
        }
        let erab = match self.erab {
            None => Some(Ok(())),
            Some(e) => e,
        };
        match (erab, self.nas) {
            (Some(Err(c)), _) | (_, Some(Err(c))) => Some(Err(c)),
            (Some(Ok(())), Some(Ok(()))) => Some(Ok(())),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
struct PendingModification {
    mme_ue_id: u64,
    peer: SocketAddr,
    seq: u32,
    sgw_teid: u32,
    pti: u8,
    /// The PDN connection and its new APN-AMBR, when it changes.
    sess_id: u64,
    apn_ambr: Option<Bitrate>,
    items: Vec<Item>,
    paged: bool,
}

/// The modifications in progress. Process-global like `bearer_activation`'s; tests
/// hold `gtp_path::S11_TEST_LOCK`.
static PENDING: Mutex<Vec<PendingModification>> = Mutex::new(Vec::new());

fn pending() -> std::sync::MutexGuard<'static, Vec<PendingModification>> {
    PENDING.lock().unwrap_or_else(|e| e.into_inner())
}

/// Number of modifications waiting. Test/diagnostic.
pub fn pending_count() -> usize {
    pending().len()
}

/// Whether the Update Bearer Request from `peer` at `seq` is being carried out.
pub fn in_flight(peer: SocketAddr, seq: u32) -> bool {
    pending().iter().any(|p| p.peer == peer && p.seq == seq)
}

/// Carry out the Serving GW's Update Bearer Request (`raw`, `seq` from `peer`).
pub fn handle_update_bearer_request(raw: &[u8], seq: u32, peer: SocketAddr) {
    if in_flight(peer, seq) {
        return;
    }
    let ctx = crate::context::mme_self();
    let mut bytes = bytes::Bytes::copy_from_slice(raw);
    let Ok(msg) = Gtp2Message::decode(&mut bytes) else {
        log::warn!("S11 Update Bearer Request seq={seq} from {peer} undecodable; dropped");
        return;
    };
    let ue = ctx
        .mme_ue_find_by_s11_local_teid(msg.header.teid.unwrap_or(0))
        .and_then(|id| ctx.mme_ue_find_by_id(id));
    let contexts: Vec<Gtp2BearerContextIe> = msg
        .get_ies(Gtp2IeType::BearerContext as u8)
        .into_iter()
        .filter(|ie| ie.instance == 0)
        .filter_map(|ie| Gtp2BearerContextIe::decode(&ie.value).ok())
        .collect();
    let Some(ue) = ue else {
        let p = PendingModification {
            mme_ue_id: 0,
            peer,
            seq,
            sgw_teid: 0,
            pti: 0,
            sess_id: 0,
            apn_ambr: None,
            items: contexts
                .iter()
                .map(|bc| refused_item(bc.ebi().unwrap_or(0), GtpCause::ContextNotFound))
                .collect(),
            paged: false,
        };
        answer(ctx, &p, GtpCause::ContextNotFound);
        return;
    };
    let sgw_teid = ctx
        .sgw_ue_find_by_id(ue.sgw_ue_id)
        .map(|s| s.sgw_s11_teid)
        .unwrap_or(0);
    // APN-AMBR (TS 29.274 §8.7): kbit/s on the wire, bit/s in the MME.
    let ambr = msg
        .get_ie(Gtp2IeType::Ambr as u8, 0)
        .filter(|ie| ie.value.len() >= 8)
        .map(|ie| Bitrate {
            uplink: u64::from(u32::from_be_bytes(ie.value[0..4].try_into().unwrap())) * 1000,
            downlink: u64::from(u32::from_be_bytes(ie.value[4..8].try_into().unwrap())) * 1000,
        });
    let pti = msg
        .get_ie(Gtp2IeType::Pti as u8, 0)
        .and_then(|ie| ie.value.first().copied())
        .unwrap_or(crate::esm_build::PTI_UNASSIGNED);
    let mut sess_id = 0;
    let mut items = Vec::new();
    for bc in &contexts {
        let ebi = bc.ebi().unwrap_or(0);
        let Some(bearer) = ctx
            .bearer_of_ue_by_ebi(ue.id, ebi)
            .and_then(|id| ctx.bearer_find_by_id(id))
        else {
            items.push(refused_item(ebi, GtpCause::ContextNotFound));
            continue;
        };
        if sess_id == 0 {
            sess_id = bearer.sess_id;
        } else if sess_id != bearer.sess_id {
            // One Update Bearer Request is about one PDN connection.
            items.push(refused_item(ebi, GtpCause::MandatoryIeIncorrect));
            continue;
        }
        let qos = bc
            .get_ie(Gtp2IeType::BearerQos as u8, 0)
            .and_then(|ie| crate::s11_handler::parse_bearer_qos(&ie.value))
            .map(|(qci, pl, pci, pvi, mbr_ul, mbr_dl, gbr_ul, gbr_dl)| {
                let mut q = bearer.qos.clone();
                q.qci = qci;
                q.arp.priority_level = pl;
                q.arp.pre_emption_capability = pci;
                q.arp.pre_emption_vulnerability = pvi;
                q.mbr = Bitrate {
                    uplink: mbr_ul,
                    downlink: mbr_dl,
                };
                q.gbr = Bitrate {
                    uplink: gbr_ul,
                    downlink: gbr_dl,
                };
                q
            });
        let tft = bc
            .get_ie(Gtp2IeType::BearerTft as u8, 0)
            .map(|ie| ie.value.to_vec())
            .filter(|t| !t.is_empty());
        items.push(Item {
            bearer_id: bearer.id,
            ebi,
            qos,
            tft,
            pkbuf: Vec::new(),
            retries: 0,
            deadline: Instant::now(),
            erab: None,
            nas: None,
            refused: None,
        });
    }
    let apn_ambr = ambr.filter(|a| {
        ctx.sess_find_by_id(sess_id)
            .is_some_and(|s| s.ambr.uplink != a.uplink || s.ambr.downlink != a.downlink)
    });
    let mut p = PendingModification {
        mme_ue_id: ue.id,
        peer,
        seq,
        sgw_teid,
        pti,
        sess_id,
        apn_ambr,
        items,
        paged: false,
    };
    if p.items.iter().all(|i| i.refused.is_some()) {
        let c = p
            .items
            .first()
            .and_then(|i| i.refused)
            .unwrap_or(GtpCause::MandatoryIeMissing);
        answer(ctx, &p, c);
        return;
    }
    let connected = ctx
        .enb_ue_find_by_id(ue.enb_ue_id)
        .is_some_and(|e| e.mme_ue_id == ue.id);
    if !connected {
        if !ue.t3413.is_running()
            && crate::paging::page_ue(ctx, ue.id, crate::context::PagingType::UpdateBearer) == 0
        {
            fail_open(&mut p, GtpCause::UnableToPageUe);
            finish(ctx, p);
            return;
        }
        p.paged = true;
        pending().push(p);
        return;
    }
    signal(ctx, &mut p);
    finish_or_keep(ctx, p);
}

fn refused_item(ebi: u8, cause: GtpCause) -> Item {
    Item {
        bearer_id: 0,
        ebi,
        qos: None,
        tft: None,
        pkbuf: Vec::new(),
        retries: 0,
        deadline: Instant::now(),
        erab: None,
        nas: None,
        refused: Some(cause),
    }
}

fn fail_open(p: &mut PendingModification, cause: GtpCause) {
    for i in p.items.iter_mut() {
        if i.outcome().is_none() {
            i.refused = Some(cause);
        }
    }
}

/// The UE-AMBR once `sess_id` has `apn_ambr` (TS 23.401 §4.7.3), when it differs from
/// the current one.
fn new_ue_ambr(
    ctx: &MmeContext,
    mme_ue_id: u64,
    sess_id: u64,
    apn_ambr: Option<Bitrate>,
) -> Option<nextgcore_s1ap::UeAmbr> {
    let apn_ambr = apn_ambr?;
    let ue = ctx.mme_ue_find_by_id(mme_ue_id)?;
    let current = crate::s1ap_build::ue_ambr_of(ctx, &ue);
    let next = crate::s1ap_build::ue_ambr(
        &ue.ambr,
        ue.sess_list
            .iter()
            .filter_map(|id| ctx.sess_find_by_id(*id))
            .filter(|s| {
                s.bearer_list
                    .iter()
                    .filter_map(|b| ctx.bearer_find_by_id(*b))
                    .any(|b| b.sgw_s1u_teid != 0)
            })
            .map(|s| {
                if s.id == sess_id {
                    apn_ambr.clone()
                } else {
                    s.ambr
                }
            }),
    );
    (next != current).then_some(next)
}

/// Step 4: one MODIFY EPS BEARER CONTEXT REQUEST per bearer, in an E-RAB MODIFY REQUEST
/// when its QoS changes, else in DOWNLINK NAS TRANSPORT; T3486 armed.
fn signal(ctx: &MmeContext, p: &mut PendingModification) {
    p.paged = false;
    let Some(mme_ue) = ctx.mme_ue_find_by_id(p.mme_ue_id) else {
        fail_open(p, GtpCause::ContextNotFound);
        return;
    };
    let Some(enb_ue) = ctx
        .enb_ue_find_by_id(mme_ue.enb_ue_id)
        .filter(|e| e.mme_ue_id == p.mme_ue_id)
    else {
        fail_open(p, GtpCause::UeNotResponding);
        return;
    };
    let mut ue_ambr = new_ue_ambr(ctx, p.mme_ue_id, p.sess_id, p.apn_ambr.clone());
    let mut first = true;
    for item in p.items.iter_mut().filter(|i| i.outcome().is_none()) {
        let Some(mut bearer) = ctx.bearer_find_by_id(item.bearer_id) else {
            item.refused = Some(GtpCause::ContextNotFound);
            continue;
        };
        if let Some(q) = &item.qos {
            bearer.qos = q.clone();
        }
        if let Some(t) = &item.tft {
            bearer.tft = t.clone();
        }
        // The APN-AMBR once, with the first bearer's request (TS 24.301 §6.4.3.2).
        let apn_ambr = p.apn_ambr.clone().filter(|_| first);
        first = false;
        let plain = crate::esm_build::build_modify_bearer_context_request_full(
            &bearer,
            p.pti,
            item.qos.is_some(),
            item.tft.is_some(),
            apn_ambr.map(|a| (a.downlink.div_ceil(1000), a.uplink.div_ceil(1000))),
        );
        let Ok(esm) = crate::nas_path::protect_esm(ctx, p.mme_ue_id, &plain) else {
            item.refused = Some(GtpCause::SystemFailure);
            continue;
        };
        let sent = if item.qos.is_some() {
            let req = nextgcore_s1ap::ErabModifyRequest {
                mme_ue_s1ap_id: enb_ue.mme_ue_s1ap_id,
                enb_ue_s1ap_id: enb_ue.enb_ue_s1ap_id,
                ue_ambr: ue_ambr.take(),
                erab_list: vec![nextgcore_s1ap::ErabToBeModifiedItem {
                    erab_id: bearer.ebi,
                    erab_qos: crate::s1ap_build::erab_qos_from_bearer(&bearer),
                    nas_pdu: esm.clone(),
                }],
            };
            item.erab = Some(None);
            crate::s1ap_gen::build_erab_modify_request(&req)
                .map_err(|e| format!("{e}"))
                .map(|pdu| {
                    crate::s1ap_path::s1ap_send(crate::s1ap_handler::S1apSend {
                        enb_id: enb_ue.enb_id,
                        pdu,
                    });
                })
        } else {
            crate::nas_path::nas_eps_send_to_downlink_nas_transport(&enb_ue, esm.clone())
                .map_err(|e| format!("{e:?}"))
        };
        match sent {
            Ok(()) => {
                item.pkbuf = esm;
                item.deadline = Instant::now() + T3486_DURATION;
            }
            Err(e) => {
                log::error!(
                    "[{}] MODIFY EPS BEARER CONTEXT for EBI {}: {e}",
                    mme_ue.imsi_bcd,
                    item.ebi
                );
                item.refused = Some(GtpCause::SystemFailure);
            }
        }
    }
    // A UE-AMBR change no E-RAB MODIFY carried: UE CONTEXT MODIFICATION (TS 36.413
    // §8.3.4, the #869 review).
    if let Some(ambr) = ue_ambr {
        match crate::s1ap_build::build_ue_context_modification_for_ue_ambr(&enb_ue, ambr) {
            Ok(pdu) => {
                crate::s1ap_path::s1ap_send(crate::s1ap_handler::S1apSend {
                    enb_id: enb_ue.enb_id,
                    pdu,
                });
            }
            Err(e) => log::error!("UE CONTEXT MODIFICATION for the UE-AMBR not built: {e:?}"),
        }
    }
}

fn finish_or_keep(ctx: &MmeContext, p: PendingModification) {
    if p.items.iter().all(|i| i.outcome().is_some()) {
        finish(ctx, p);
    } else {
        pending().push(p);
    }
}

/// Store what every accepted bearer now has, then answer.
fn finish(ctx: &MmeContext, p: PendingModification) {
    let mut any = false;
    for item in &p.items {
        if item.outcome() == Some(Ok(())) {
            any = true;
            if let Some(b) = ctx.bearer_pool.write().unwrap().get_mut(&item.bearer_id) {
                if let Some(q) = &item.qos {
                    b.qos = q.clone();
                }
                if let Some(t) = &item.tft {
                    b.tft = t.clone();
                }
            }
        }
    }
    if any {
        if let Some(a) = &p.apn_ambr {
            if let Some(s) = ctx.sess_pool.write().unwrap().get_mut(&p.sess_id) {
                s.ambr = a.clone();
            }
        }
    }
    let c = p
        .items
        .iter()
        .find_map(|i| i.outcome().and_then(|o| o.err()))
        .unwrap_or(GtpCause::RequestAccepted);
    answer(ctx, &p, c);
}

fn update(ctx: &MmeContext, mme_ue_id: u64, ebi: u8, f: impl FnOnce(&mut Item)) -> bool {
    let done = {
        let mut list = pending();
        let Some(i) = list.iter().position(|p| {
            p.mme_ue_id == mme_ue_id
                && !p.paged
                && p.items.iter().any(|it| it.ebi == ebi && it.bearer_id != 0)
        }) else {
            return false;
        };
        if let Some(item) = list[i]
            .items
            .iter_mut()
            .find(|it| it.ebi == ebi && it.bearer_id != 0)
        {
            f(item);
        }
        if list[i].items.iter().all(|it| it.outcome().is_some()) {
            Some(list.remove(i))
        } else {
            None
        }
    };
    if let Some(p) = done {
        finish(ctx, p);
    }
    true
}

/// Step 5: the E-RAB MODIFY RESPONSE of `mme_ue_id`.
pub fn on_erab_modify(ctx: &MmeContext, mme_ue_id: u64, modified: &[u8], failed: &[u8]) {
    for &ebi in modified {
        update(ctx, mme_ue_id, ebi, |i| {
            if i.erab.is_some() {
                i.erab = Some(Some(Ok(())));
            }
        });
    }
    for &ebi in failed {
        update(ctx, mme_ue_id, ebi, |i| {
            if i.erab.is_some() {
                i.erab = Some(Some(Err(GtpCause::RequestRejectedReasonNotSpecified)));
            }
        });
    }
}

/// Step 7: MODIFY EPS BEARER CONTEXT ACCEPT for `ebi`.
pub fn on_accept(ctx: &MmeContext, mme_ue_id: u64, ebi: u8) -> bool {
    update(ctx, mme_ue_id, ebi, |i| i.nas = Some(Ok(())))
}

/// MODIFY EPS BEARER CONTEXT REJECT for `ebi` (TS 24.301 §6.4.3.4): "UE refuses".
pub fn on_reject(ctx: &MmeContext, mme_ue_id: u64, ebi: u8) -> bool {
    update(ctx, mme_ue_id, ebi, |i| {
        i.nas = Some(Err(GtpCause::UeRefuses))
    })
}

fn take_paged(mme_ue_id: u64) -> Vec<PendingModification> {
    let mut list = pending();
    let (taken, kept): (Vec<_>, Vec<_>) = list
        .drain(..)
        .partition(|p| p.mme_ue_id == mme_ue_id && p.paged);
    *list = kept;
    taken
}

/// `mme_ue_id` is ECM-CONNECTED again after paging.
pub fn on_connected(ctx: &MmeContext, mme_ue_id: u64) {
    for mut p in take_paged(mme_ue_id) {
        signal(ctx, &mut p);
        finish_or_keep(ctx, p);
    }
}

/// The paging of `mme_ue_id` failed: "Unable to page UE".
pub fn on_paging_failed(ctx: &MmeContext, mme_ue_id: u64) {
    for mut p in take_paged(mme_ue_id) {
        fail_open(&mut p, GtpCause::UnableToPageUe);
        finish(ctx, p);
    }
}

/// Answer every modification of `mme_ue_id` at once (the UE is detached).
pub fn settle_all_for_ue(ctx: &MmeContext, mme_ue_id: u64) {
    let all: Vec<PendingModification> = {
        let mut list = pending();
        let (taken, kept): (Vec<_>, Vec<_>) =
            list.drain(..).partition(|p| p.mme_ue_id == mme_ue_id);
        *list = kept;
        taken
    };
    for mut p in all {
        fail_open(&mut p, GtpCause::ContextNotFound);
        finish(ctx, p);
    }
}

/// Step 8: the Update Bearer Response (TS 29.274 §7.2.16, Table 7.2.16-2).
fn answer(_ctx: &MmeContext, p: &PendingModification, first_failure: GtpCause) {
    let set = p
        .items
        .iter()
        .filter(|i| i.outcome() == Some(Ok(())))
        .count();
    let cause = match set {
        0 => first_failure,
        n if n == p.items.len() => GtpCause::RequestAccepted,
        _ => GtpCause::RequestAcceptedPartially,
    };
    let mut rsp = Gtp2Message::new(nextgcore_gtp::v2::Gtp2Header::new(
        crate::s11_build::message_type::UPDATE_BEARER_RESPONSE,
        p.sgw_teid,
        p.seq,
    ));
    rsp.add_ie(Gtp2CauseIe::new(cause as u8).to_ie(0));
    for item in &p.items {
        let c = match item.outcome() {
            Some(Ok(())) => GtpCause::RequestAccepted,
            Some(Err(c)) => c,
            None => GtpCause::UeNotResponding,
        };
        let mut bc = Gtp2BearerContextIe::new();
        bc.set_ebi(item.ebi);
        bc.set_cause(&Gtp2CauseIe::new(c as u8));
        rsp.add_bearer_context(0, &bc);
    }
    log::info!(
        "S11 Update Bearer Response to {} (seq {}): cause {}, {set} of {} bearer(s) modified \
         (TS 23.401 §5.4.2.1 step 8)",
        p.peer,
        p.seq,
        cause as u8,
        p.items.len()
    );
    if let Err(e) = crate::gtp_path::send_response_to_sgwc(p.peer, &rsp) {
        log::error!("S11 Update Bearer Response to {} failed: {e}", p.peer);
    }
}

/// Drive T3486 (TS 24.301 §6.4.3.5).
pub fn sweep(ctx: &MmeContext, now: Instant) {
    if !std::ptr::eq(ctx, crate::context::mme_self()) {
        return;
    }
    let mut resend = Vec::new();
    let mut done = Vec::new();
    {
        let mut list = pending();
        for p in list.iter_mut().filter(|p| !p.paged) {
            let connected = ctx.mme_ue_find_by_id(p.mme_ue_id).is_some_and(|ue| {
                ctx.enb_ue_find_by_id(ue.enb_ue_id)
                    .is_some_and(|e| e.mme_ue_id == p.mme_ue_id)
            });
            for item in p.items.iter_mut().filter(|i| i.outcome().is_none()) {
                if !connected {
                    item.refused = Some(GtpCause::UeNotResponding);
                } else if item.nas.is_none() && now >= item.deadline {
                    if item.retries >= T3486_RETRANSMISSIONS {
                        item.nas = Some(Err(GtpCause::UeNotResponding));
                    } else {
                        item.retries += 1;
                        item.deadline = now + T3486_DURATION;
                        resend.push((p.mme_ue_id, item.pkbuf.clone()));
                    }
                }
            }
        }
        let mut i = 0;
        while i < list.len() {
            if !list[i].paged && list[i].items.iter().all(|it| it.outcome().is_some()) {
                done.push(list.remove(i));
            } else {
                i += 1;
            }
        }
    }
    for (mme_ue_id, pkbuf) in resend {
        if let Some(enb_ue) = ctx
            .mme_ue_find_by_id(mme_ue_id)
            .and_then(|ue| ctx.enb_ue_find_by_id(ue.enb_ue_id))
        {
            let _ = crate::nas_path::nas_eps_send_to_downlink_nas_transport(&enb_ue, pkbuf);
        }
    }
    for p in done {
        finish(ctx, p);
    }
}

/// Force every T3486 of `mme_ue_id` to have expired. Test-only.
#[cfg(test)]
pub(crate) fn expire_for_test(mme_ue_id: u64) {
    for p in pending().iter_mut().filter(|p| p.mme_ue_id == mme_ue_id) {
        for i in p.items.iter_mut() {
            i.deadline = Instant::now() - Duration::from_millis(1);
        }
    }
}

/// Drop every pending modification. Test-only.
#[cfg(test)]
pub(crate) fn clear_for_test() {
    pending().clear();
}
