//! Dedicated bearer activation by the network, towards the eNB and the UE (#641,
//! TS 23.401 §5.4.1 steps 3-8, TS 24.301 §6.4.2).
//!
//! The Serving GW's Create Bearer Request used to be refused with "Service not
//! supported" (#1153, the stop-gap). This module carries it out:
//! 1. **Bearers.** Each Bearer Context gets an EBI. The MME allocates it: the lowest
//!    of 5..=15 the UE does not use (TS 23.401 §5.4.1 step 4, TS 24.301 §6.4.2.2). The
//!    bearer is stored with its QoS, its TFT, the S1-U SGW F-TEID (Table 7.2.3-2,
//!    instance 0) and the PGW's S5/S8-U F-TEID (instance 1).
//! 2. **Signalling.** For an ECM-CONNECTED UE, one E-RAB SETUP REQUEST per bearer goes
//!    out, carrying its ACTIVATE DEDICATED EPS BEARER CONTEXT REQUEST (step 4), and T3485
//!    is armed (TS 24.301 §6.4.2.2).
//!    - An ECM-IDLE UE is paged first (`PagingType::CreateBearer`, step 3).
//!    - While an Attach is still running, the request waits for the ATTACH COMPLETE (TS
//!      23.401 Annex F NOTE 2).
//! 3. **The join.** A bearer is set up when both its E-RAB SETUP RESPONSE item (step 5,
//!    the eNB's S1-U F-TEID) and the UE's ACTIVATE DEDICATED EPS BEARER CONTEXT ACCEPT
//!    (step 7) have arrived. It fails on an E-RAB failure, a REJECT (ESM cause → "UE
//!    refuses"), or the fifth T3485 expiry ("UE not responding", TS 24.301 §6.4.2.6). An
//!    E-RAB the eNB set up for a bearer that failed is released again.
//! 4. **The answer** (step 8, TS 29.274 §7.2.4). Once every bearer is settled, the Create
//!    Bearer Response goes out under the request's sequence number:
//!    - each set-up bearer with its EBI, cause 16, the S1-U eNodeB F-TEID (instance 0)
//!      and the S1-U SGW F-TEID (instance 1);
//!    - each failed one with its cause;
//!    - message cause 16, 17 or the first failure's.
//!
//!    A failed bearer is removed in the MME.
//!
//! Lock order: [`PENDING`] is never taken while a context pool lock is held, and pool
//! locks taken under it are taken one at a time (as in `bearer_deactivation`).

use std::net::SocketAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use nextgcore_gtp::v2::{Gtp2BearerContextIe, Gtp2CauseIe, Gtp2FTeidIe, Gtp2IeType, Gtp2Message};

use crate::context::{IpAddr, MmeContext};
use crate::s11_build::{f_teid_interface as iface, GtpCause};

/// T3485 (TS 24.301 Table 10.3.2): 8 s.
pub const T3485_DURATION: Duration = Duration::from_secs(8);
/// Retransmissions before the fifth expiry aborts the procedure (§6.4.2.6).
const T3485_RETRANSMISSIONS: u32 = 4;

/// How long the MME may take to answer a Create Bearer Request (#1216 review M5,
/// #1228).
///
/// The Serving GW relays the request under its S11 transaction and gives up
/// after it: it removes the bearer at the SGW-U and answers the PDN GW "Remote
/// peer not responding" (sgwcd `dedicated_bearer::mme_silent`). An answer after
/// that would set the bearer up in the MME, the eNB and the UE only. sgwcd runs
/// the paging-dependent bearer Requests with their own N3 (TS 29.274 §7.6),
/// 3 s x (17 + 1) = 54 s, and the PGW its S5/S8 one for 60 s; the MME answers
/// within `nextgcore_gtp::v2::xact::MME_BEARER_PROCEDURE_BUDGET` (50 s), which
/// covers T3485 x 5 (40 s, TS 24.301 §6.4.2.6) and about 10 s of paging.
/// Whatever is unsettled by then fails, paging "Unable to page UE", anything
/// else "UE not responding".
pub fn answer_budget() -> Duration {
    nextgcore_gtp::v2::xact::MME_BEARER_PROCEDURE_BUDGET
}

/// Whether `ue` is in an Attach that has not completed (Annex F NOTE 2). A UE
/// that registered by TAU, or arrived by an N26 handover, never had an Attach
/// in this MME and is not waited on.
fn attach_in_progress(ue: &crate::context::MmeUe) -> bool {
    !ue.attach_completed && ue.nas_eps.type_ == crate::context::MmeEpsType::AttachRequest
}

/// One bearer of a Create Bearer Request.
#[derive(Debug, Clone)]
struct Item {
    /// The bearer in the pool; 0 for a Bearer Context refused before one was created.
    bearer_id: u64,
    ebi: u8,
    /// The protected ESM message, for T3485 retransmission (empty until signalled).
    pkbuf: Vec<u8>,
    retries: u32,
    deadline: Instant,
    /// The eNB's answer for the E-RAB: set up, or failed with the cause to report.
    erab: Option<Result<(), GtpCause>>,
    /// The UE's answer: ACCEPT, or the cause to report.
    nas: Option<Result<(), GtpCause>>,
    /// Settled before signalling (no EBI, a missing IE, ...).
    refused: Option<GtpCause>,
}

impl Item {
    fn outcome(&self) -> Option<Result<(), GtpCause>> {
        if let Some(c) = self.refused {
            return Some(Err(c));
        }
        match (self.erab, self.nas) {
            (Some(Err(c)), _) | (_, Some(Err(c))) => Some(Err(c)),
            (Some(Ok(())), Some(Ok(()))) => Some(Ok(())),
            _ => None,
        }
    }
}

/// Why a request is waiting before it is signalled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Parked {
    /// Signalled: E-RAB SETUP and the NAS request are out.
    No,
    /// The ECM-IDLE UE is being paged (step 3).
    Paging,
    /// The Attach has not completed (Annex F NOTE 2).
    Attach,
}

/// A Create Bearer Request whose answer waits for the eNB and the UE.
#[derive(Debug, Clone)]
struct PendingActivation {
    mme_ue_id: u64,
    peer: SocketAddr,
    seq: u32,
    sgw_teid: u32,
    linked_ebi: u8,
    /// The UE's PTI when the request answers its Bearer Resource Allocation (Table
    /// 7.2.3-1), else unassigned.
    pti: u8,
    items: Vec<Item>,
    parked: Parked,
    /// When the request arrived: the answer is due by [`answer_budget`] after it.
    received: Instant,
}

/// The activations in progress. Process-global like `bearer_deactivation`'s;
/// tests hold `gtp_path::S11_TEST_LOCK`.
static PENDING: Mutex<Vec<PendingActivation>> = Mutex::new(Vec::new());

fn pending() -> std::sync::MutexGuard<'static, Vec<PendingActivation>> {
    PENDING.lock().unwrap_or_else(|e| e.into_inner())
}

/// Number of activations waiting. Test/diagnostic.
pub fn pending_count() -> usize {
    pending().len()
}

/// Whether the Create Bearer Request from `peer` at `seq` is already being carried
/// out: a retransmission is not acted on twice (TS 29.274 §7.6).
pub fn in_flight(peer: SocketAddr, seq: u32) -> bool {
    pending().iter().any(|p| p.peer == peer && p.seq == seq)
}

/// A Bearer Context of the request.
struct Requested {
    tft: Option<Vec<u8>>,
    qos: Option<(u8, u8, u8, u8, u64, u64, u64, u64)>,
    /// A Bearer QoS IE is present (it may still not parse).
    qos_present: bool,
    sgw_s1u: Option<Gtp2FTeidIe>,
    pgw_s5u: Option<Gtp2FTeidIe>,
}

fn ip_of(f: &Gtp2FTeidIe) -> IpAddr {
    IpAddr {
        ipv4: f.ipv4_addr,
        ipv6: f.ipv6_addr,
    }
}

/// The lowest EPS bearer identity in 5..=15 that `mme_ue_id` does not use.
fn free_ebi(ctx: &MmeContext, mme_ue_id: u64, taken: &[u8]) -> Option<u8> {
    (crate::context::MIN_EPS_BEARER_ID..=crate::context::MAX_EPS_BEARER_ID)
        .find(|e| !taken.contains(e) && ctx.bearer_find_by_ebi(mme_ue_id, *e).is_none())
}

/// Carry out the Serving GW's Create Bearer Request (`raw`, `seq` from `peer`).
///
/// `in_flight` and the later `pending().push` are not one critical section; that
/// is safe because S11 requests are dispatched on one thread.
pub fn handle_create_bearer_request(raw: &[u8], seq: u32, peer: SocketAddr) {
    if in_flight(peer, seq) {
        log::debug!(
            "S11 Create Bearer Request seq={seq} from {peer} is being carried out; \
             retransmission ignored"
        );
        return;
    }
    let ctx = crate::context::mme_self();
    let mut bytes = bytes::Bytes::copy_from_slice(raw);
    let Ok(msg) = Gtp2Message::decode(&mut bytes) else {
        log::warn!("S11 Create Bearer Request seq={seq} from {peer} undecodable; dropped");
        return;
    };
    let local_teid = msg.header.teid.unwrap_or(0);
    let ue = ctx
        .mme_ue_find_by_s11_local_teid(local_teid)
        .and_then(|id| ctx.mme_ue_find_by_id(id));
    let requested: Vec<Requested> = msg
        .get_ies(Gtp2IeType::BearerContext as u8)
        .into_iter()
        .filter(|ie| ie.instance == 0)
        .filter_map(|ie| Gtp2BearerContextIe::decode(&ie.value).ok())
        .map(|bc| Requested {
            tft: bc
                .get_ie(Gtp2IeType::BearerTft as u8, 0)
                .map(|ie| ie.value.to_vec())
                .filter(|t| !t.is_empty()),
            qos: bc
                .get_ie(Gtp2IeType::BearerQos as u8, 0)
                .and_then(|ie| crate::s11_handler::parse_bearer_qos(&ie.value)),
            qos_present: bc.get_ie(Gtp2IeType::BearerQos as u8, 0).is_some(),
            sgw_s1u: bc
                .fteid(0)
                .ok()
                .flatten()
                .filter(|f| f.interface_type == iface::S1U_SGW_GTP_U),
            pgw_s5u: bc.fteid(1).ok().flatten(),
        })
        .collect();
    let answer_now = |sgw_teid: u32, cause: GtpCause, n: usize| {
        let ebis = vec![0u8; n.max(1)];
        match crate::s11_build::build_create_bearer_refusal(sgw_teid, &ebis, cause, seq) {
            Ok(rsp) => {
                if let Err(e) = crate::gtp_path::send_response_to_sgwc(peer, &rsp) {
                    log::error!("S11 Create Bearer Response to {peer} failed: {e}");
                }
            }
            Err(e) => log::error!("Create Bearer Response build failed: {e}"),
        }
    };
    let Some(ue) = ue else {
        log::warn!("S11 Create Bearer Request seq={seq}: TEID {local_teid:#x} names no UE");
        answer_now(0, GtpCause::ContextNotFound, requested.len());
        return;
    };
    let sgw_teid = ctx
        .sgw_ue_find_by_id(ue.sgw_ue_id)
        .map(|s| s.sgw_s11_teid)
        .unwrap_or(0);
    let Some(linked_ebi) = msg
        .get_ie(Gtp2IeType::Ebi as u8, 0)
        .and_then(|ie| ie.value.first().map(|v| v & 0x0f))
    else {
        // #1216 review: the Linked EBI is M (Table 7.2.3-1): 70 Mandatory IE
        // missing, naming it as the Offending IE (§8.4: type, length 0, instance).
        log::warn!("S11 Create Bearer Request seq={seq}: no Linked EBI");
        let mut rsp = Gtp2Message::new(nextgcore_gtp::v2::Gtp2Header::new(
            crate::s11_build::message_type::CREATE_BEARER_RESPONSE,
            sgw_teid,
            seq,
        ));
        rsp.add_ie(nextgcore_gtp::v2::Gtp2Ie::from_slice(
            Gtp2IeType::Cause as u8,
            0,
            &[
                GtpCause::MandatoryIeMissing as u8,
                0,
                Gtp2IeType::Ebi as u8,
                0,
                0,
                0,
            ],
        ));
        if let Err(e) = crate::gtp_path::send_response_to_sgwc(peer, &rsp) {
            log::error!("S11 Create Bearer Response to {peer} failed: {e}");
        }
        return;
    };
    // The PDN connection: the one whose default bearer is the Linked EBI.
    let sess = ue
        .sess_list
        .iter()
        .filter_map(|id| ctx.sess_find_by_id(*id))
        .find(|s| {
            s.bearer_list
                .first()
                .and_then(|b| ctx.bearer_find_by_id(*b))
                .is_some_and(|b| b.ebi == linked_ebi && linked_ebi != 0)
        });
    let Some(sess) = sess else {
        log::warn!(
            "[{}] S11 Create Bearer Request seq={seq}: LBI {linked_ebi} is no PDN connection of \
             the UE",
            ue.imsi_bcd
        );
        answer_now(sgw_teid, GtpCause::ContextNotFound, requested.len());
        return;
    };
    if requested.is_empty() {
        answer_now(sgw_teid, GtpCause::MandatoryIeMissing, 1);
        return;
    }
    let pti = msg
        .get_ie(Gtp2IeType::Pti as u8, 0)
        .and_then(|ie| ie.value.first().copied())
        .unwrap_or(crate::esm_build::PTI_UNASSIGNED);

    // Step 4: an EBI and a stored bearer per Bearer Context.
    let mut items = Vec::new();
    let mut taken = Vec::new();
    for r in requested {
        let refused = |c: GtpCause| Item {
            bearer_id: 0,
            ebi: 0,
            pkbuf: Vec::new(),
            retries: 0,
            deadline: Instant::now(),
            erab: None,
            nas: None,
            refused: Some(c),
        };
        let (Some(tft), Some(qos)) = (r.tft, r.qos) else {
            // #1216 review: a Bearer QoS that is there but does not parse (under
            // 22 octets) is "Mandatory IE incorrect", not "missing".
            let cause = if r.qos_present && r.qos.is_none() {
                GtpCause::MandatoryIeIncorrect
            } else {
                GtpCause::MandatoryIeMissing
            };
            items.push(refused(cause));
            continue;
        };
        let Some(sgw_s1u) = r.sgw_s1u else {
            items.push(refused(GtpCause::ConditionalIeMissing));
            continue;
        };
        let Some(ebi) = free_ebi(ctx, ue.id, &taken) else {
            items.push(refused(GtpCause::NoResourcesAvailable));
            continue;
        };
        taken.push(ebi);
        let bearer_id = ctx.bearer_add(sess.id, ue.id);
        if let Some(b) = ctx.bearer_pool.write().unwrap().get_mut(&bearer_id) {
            let (qci, pl, pci, pvi, mbr_ul, mbr_dl, gbr_ul, gbr_dl) = qos;
            b.ebi = ebi;
            b.qos.qci = qci;
            b.qos.arp.priority_level = pl;
            b.qos.arp.pre_emption_capability = pci;
            b.qos.arp.pre_emption_vulnerability = pvi;
            b.qos.mbr.uplink = mbr_ul;
            b.qos.mbr.downlink = mbr_dl;
            b.qos.gbr.uplink = gbr_ul;
            b.qos.gbr.downlink = gbr_dl;
            b.tft = tft;
            b.sgw_s1u_teid = sgw_s1u.teid;
            b.sgw_s1u_ip = ip_of(&sgw_s1u);
            if let Some(p) = r.pgw_s5u.as_ref() {
                b.pgw_s5u_teid = p.teid;
                b.pgw_s5u_ip = ip_of(p);
            }
        }
        // #1216 review B1: the bearer joins the session's bearer list only once
        // it is set up (`answer`). Until then no other procedure (a Service
        // Request's or TAU's Initial Context Setup, a Modify Bearer Request, a
        // handover's E-RAB lists, a TAU ACCEPT's EPS bearer context status)
        // carries it; only this module's E-RAB SETUP does.
        items.push(Item {
            bearer_id,
            ebi,
            pkbuf: Vec::new(),
            retries: 0,
            deadline: Instant::now(),
            erab: None,
            nas: None,
            refused: None,
        });
    }
    let mut p = PendingActivation {
        mme_ue_id: ue.id,
        peer,
        seq,
        sgw_teid,
        linked_ebi,
        pti,
        items,
        parked: Parked::No,
        received: Instant::now(),
    };
    if p.items.iter().all(|i| i.refused.is_some()) {
        answer(ctx, &p);
        return;
    }

    let connected = ctx
        .enb_ue_find_by_id(ue.enb_ue_id)
        .is_some_and(|e| e.mme_ue_id == ue.id);
    if !connected {
        // Step 3: page the ECM-IDLE UE; the request is signalled once it answers.
        let paging = ue.t3413.is_running();
        if !paging
            && crate::paging::page_ue(ctx, ue.id, crate::context::PagingType::CreateBearer) == 0
        {
            log::warn!(
                "[{}] Create Bearer Request: the ECM-IDLE UE cannot be paged",
                ue.imsi_bcd
            );
            fail_unsignalled(&mut p, GtpCause::UnableToPageUe);
            answer(ctx, &p);
            return;
        }
        log::info!(
            "[{}] Create Bearer Request for EBIs {:?}: the UE is ECM-IDLE and paged (TS 23.401 \
             §5.4.1 step 3)",
            ue.imsi_bcd,
            ebis_of(&p)
        );
        p.parked = Parked::Paging;
        pending().push(p);
        return;
    }
    if attach_in_progress(&ue) {
        // Annex F NOTE 2: no separate Bearer Setup before the Attach completes.
        log::info!(
            "[{}] Create Bearer Request for EBIs {:?} during the Attach: held until ATTACH \
             COMPLETE (TS 23.401 Annex F)",
            ue.imsi_bcd,
            ebis_of(&p)
        );
        p.parked = Parked::Attach;
        pending().push(p);
        return;
    }
    signal(ctx, &mut p);
    finish_or_keep(ctx, p);
}

fn ebis_of(p: &PendingActivation) -> Vec<u8> {
    p.items
        .iter()
        .filter(|i| i.bearer_id != 0)
        .map(|i| i.ebi)
        .collect()
}

/// Every bearer not yet answered fails with `cause`.
fn fail_unsignalled(p: &mut PendingActivation, cause: GtpCause) {
    for i in p.items.iter_mut() {
        if i.outcome().is_none() {
            i.refused = Some(cause);
        }
    }
}

/// Step 4: one E-RAB SETUP REQUEST per bearer, carrying its ACTIVATE DEDICATED EPS
/// BEARER CONTEXT REQUEST; T3485 armed.
fn signal(ctx: &MmeContext, p: &mut PendingActivation) {
    p.parked = Parked::No;
    let Some(mme_ue) = ctx.mme_ue_find_by_id(p.mme_ue_id) else {
        fail_unsignalled(p, GtpCause::ContextNotFound);
        return;
    };
    let Some(enb_ue) = ctx
        .enb_ue_find_by_id(mme_ue.enb_ue_id)
        .filter(|e| e.mme_ue_id == p.mme_ue_id)
    else {
        fail_unsignalled(p, GtpCause::UeNotResponding);
        return;
    };
    for item in p.items.iter_mut().filter(|i| i.outcome().is_none()) {
        let Some(bearer) = ctx.bearer_find_by_id(item.bearer_id) else {
            item.refused = Some(GtpCause::SystemFailure);
            continue;
        };
        let plain = crate::esm_build::build_activate_dedicated_bearer_context_request_with_params(
            &bearer,
            p.linked_ebi,
            p.pti,
        );
        let sent = crate::nas_path::protect_esm(ctx, p.mme_ue_id, &plain)
            .map_err(|e| format!("not protected: {e:?}"))
            .and_then(|esm| {
                crate::s1ap_build::build_e_rab_setup_request(&enb_ue, &bearer, &esm, None)
                    .map_err(|e| format!("E-RAB Setup Request not built: {e:?}"))
                    .map(|pdu| (esm, pdu))
            })
            .and_then(|(esm, pdu)| {
                crate::nas_path::nas_eps_send_to_enb(&mme_ue, &enb_ue, pdu)
                    .map_err(|e| format!("not sent: {e:?}"))
                    .map(|_| esm)
            });
        match sent {
            Ok(esm) => {
                item.pkbuf = esm;
                item.retries = 0;
                item.deadline = Instant::now() + T3485_DURATION;
            }
            Err(e) => {
                log::error!(
                    "[{}] ACTIVATE DEDICATED EPS BEARER CONTEXT REQUEST for EBI {}: {e}",
                    mme_ue.imsi_bcd,
                    item.ebi
                );
                item.refused = Some(GtpCause::SystemFailure);
            }
        }
    }
    log::info!(
        "[{}] E-RAB SETUP REQUEST with ACTIVATE DEDICATED EPS BEARER CONTEXT REQUEST for EBIs \
         {:?} (LBI {}), T3485 armed (TS 23.401 §5.4.1 step 4)",
        mme_ue.imsi_bcd,
        ebis_of(p),
        p.linked_ebi
    );
}

/// Answer and drop `p` when every bearer is settled, else keep it pending.
fn finish_or_keep(ctx: &MmeContext, p: PendingActivation) {
    if p.items.iter().all(|i| i.outcome().is_some()) {
        answer(ctx, &p);
    } else {
        pending().push(p);
    }
}

/// Settle what `f` changes on the activation of `mme_ue_id` holding `ebi`, then answer it
/// if that was its last bearer.
fn update(ctx: &MmeContext, mme_ue_id: u64, ebi: u8, f: impl FnOnce(&mut Item)) -> bool {
    let done = {
        let mut list = pending();
        let Some(i) = list.iter().position(|p| {
            p.mme_ue_id == mme_ue_id
                && p.parked == Parked::No
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
        answer(ctx, &p);
    }
    true
}

/// Step 5: the E-RAB SETUP RESPONSE of `mme_ue_id`: `set_up` E-RAB ids (the eNB's
/// F-TEIDs are already stored by `s1ap_handler`) and `failed` ones.
pub fn on_erab_setup(ctx: &MmeContext, mme_ue_id: u64, set_up: &[u8], failed: &[u8]) {
    for &ebi in set_up {
        update(ctx, mme_ue_id, ebi, |i| i.erab = Some(Ok(())));
    }
    for &ebi in failed {
        // The eNB could not set the radio bearer up; the NAS request it carried may
        // never reach the UE, so the bearer is not waited for any further.
        update(ctx, mme_ue_id, ebi, |i| {
            i.erab = Some(Err(GtpCause::RequestRejectedReasonNotSpecified))
        });
    }
}

/// Step 7: ACTIVATE DEDICATED EPS BEARER CONTEXT ACCEPT for `ebi`. Returns whether it
/// answered an activation this module started.
pub fn on_accept(ctx: &MmeContext, mme_ue_id: u64, ebi: u8) -> bool {
    update(ctx, mme_ue_id, ebi, |i| i.nas = Some(Ok(())))
}

/// ACTIVATE DEDICATED EPS BEARER CONTEXT REJECT for `ebi` (TS 24.301 §6.4.2.5): the
/// bearer is not created, "UE refuses" (TS 29.274 §7.2.4).
pub fn on_reject(ctx: &MmeContext, mme_ue_id: u64, ebi: u8) -> bool {
    update(ctx, mme_ue_id, ebi, |i| {
        i.nas = Some(Err(GtpCause::UeRefuses))
    })
}

/// Take the activations of `mme_ue_id` parked for `why`.
fn take_parked(mme_ue_id: u64, why: Parked) -> Vec<PendingActivation> {
    let mut list = pending();
    let (taken, kept): (Vec<_>, Vec<_>) = list
        .drain(..)
        .partition(|p| p.mme_ue_id == mme_ue_id && p.parked == why);
    *list = kept;
    taken
}

/// `mme_ue_id` is ECM-CONNECTED again after paging: its parked activations are
/// signalled now (step 3 → 4).
pub fn on_connected(ctx: &MmeContext, mme_ue_id: u64) {
    for mut p in take_parked(mme_ue_id, Parked::Paging) {
        signal(ctx, &mut p);
        finish_or_keep(ctx, p);
    }
}

/// The ATTACH COMPLETE of `mme_ue_id` arrived: activations held for it are signalled
/// (Annex F NOTE 2).
pub fn on_attach_complete(ctx: &MmeContext, mme_ue_id: u64) {
    for mut p in take_parked(mme_ue_id, Parked::Attach) {
        signal(ctx, &mut p);
        finish_or_keep(ctx, p);
    }
}

/// The paging of `mme_ue_id` failed: its parked activations are refused "Unable to
/// page UE" (TS 29.274 §7.2.4).
pub fn on_paging_failed(ctx: &MmeContext, mme_ue_id: u64) {
    for mut p in take_parked(mme_ue_id, Parked::Paging) {
        fail_unsignalled(&mut p, GtpCause::UnableToPageUe);
        answer(ctx, &p);
    }
}

/// Settle every activation of `mme_ue_id` at once (the UE is being detached).
pub fn settle_all_for_ue(ctx: &MmeContext, mme_ue_id: u64) {
    let all: Vec<PendingActivation> = {
        let mut list = pending();
        let (taken, kept): (Vec<_>, Vec<_>) =
            list.drain(..).partition(|p| p.mme_ue_id == mme_ue_id);
        *list = kept;
        taken
    };
    for mut p in all {
        fail_unsignalled(&mut p, GtpCause::ContextNotFound);
        answer(ctx, &p);
    }
}

/// Remove bearer `bearer_id` in the MME.
fn remove_bearer(ctx: &MmeContext, bearer_id: u64) {
    if let Some(bearer) = ctx.bearer_find_by_id(bearer_id) {
        if let Some(sess) = ctx.sess_pool.write().unwrap().get_mut(&bearer.sess_id) {
            sess.bearer_list.retain(|id| *id != bearer_id);
        }
    }
    ctx.bearer_remove(bearer_id);
}

/// Release at the eNB the E-RABs of failed bearers it did set up (no NAS message: the
/// UE either refused the bearer or never answered).
fn release_erabs(ctx: &MmeContext, mme_ue_id: u64, erabs: &[u8]) {
    if erabs.is_empty() {
        return;
    }
    let Some(enb_ue) = ctx
        .mme_ue_find_by_id(mme_ue_id)
        .and_then(|ue| ctx.enb_ue_find_by_id(ue.enb_ue_id))
        .filter(|e| e.mme_ue_id == mme_ue_id)
    else {
        return;
    };
    let cmd = nextgcore_s1ap::ErabReleaseCommand {
        mme_ue_s1ap_id: enb_ue.mme_ue_s1ap_id,
        enb_ue_s1ap_id: enb_ue.enb_ue_s1ap_id,
        ue_ambr: None,
        erab_list: erabs
            .iter()
            .map(|erab_id| nextgcore_s1ap::ErabItem {
                erab_id: *erab_id,
                cause: nextgcore_s1ap::Cause::Nas(nextgcore_s1ap::CauseNas::Unspecified),
            })
            .collect(),
        nas_pdu: None,
    };
    match crate::s1ap_gen::build_erab_release_command(&cmd) {
        Ok(pdu) => {
            crate::s1ap_path::s1ap_send(crate::s1ap_handler::S1apSend {
                enb_id: enb_ue.enb_id,
                pdu,
            });
        }
        Err(e) => log::error!("E-RAB Release Command for {erabs:?} not built: {e}"),
    }
}

/// Step 8: the Create Bearer Response, and the failed bearers removed.
fn answer(ctx: &MmeContext, p: &PendingActivation) {
    let mut rsp = Gtp2Message::new(nextgcore_gtp::v2::Gtp2Header::new(
        crate::s11_build::message_type::CREATE_BEARER_RESPONSE,
        p.sgw_teid,
        p.seq,
    ));
    let mut set_up = 0usize;
    let mut first_failure = None;
    let mut contexts = Vec::new();
    let mut release = Vec::new();
    for item in &p.items {
        let outcome = item.outcome().unwrap_or(Err(GtpCause::UeNotResponding));
        let mut bc = Gtp2BearerContextIe::new();
        bc.set_ebi(item.ebi);
        match outcome {
            Ok(()) => {
                set_up += 1;
                bc.set_cause(&Gtp2CauseIe::new(GtpCause::RequestAccepted as u8));
                if let Some(bearer) = ctx.bearer_find_by_id(item.bearer_id) {
                    // #1216 review M4: v4, v6 or dual, as the bearer's addresses are.
                    let fteid = crate::s11_build::fteid_of;
                    if let Some(f) = fteid(
                        iface::S1U_ENB_GTP_U,
                        bearer.enb_s1u_teid,
                        &bearer.enb_s1u_ip,
                    ) {
                        bc.set_fteid(0, &f);
                    }
                    if let Some(f) = fteid(
                        iface::S1U_SGW_GTP_U,
                        bearer.sgw_s1u_teid,
                        &bearer.sgw_s1u_ip,
                    ) {
                        bc.set_fteid(1, &f);
                    }
                    // B1: set up, so it is now one of the session's bearers.
                    if let Some(s) = ctx.sess_pool.write().unwrap().get_mut(&bearer.sess_id) {
                        if !s.bearer_list.contains(&item.bearer_id) {
                            s.bearer_list.push(item.bearer_id);
                        }
                    }
                    // #1015: the Serving GW now holds this eNB tunnel.
                    if let Some(b) = ctx.bearer_pool.write().unwrap().get_mut(&item.bearer_id) {
                        b.enb_s1u_at_sgw = Some((b.enb_s1u_teid, b.enb_s1u_ip.clone()));
                    }
                }
            }
            Err(cause) => {
                first_failure.get_or_insert(cause);
                bc.set_cause(&Gtp2CauseIe::new(cause as u8));
                if item.bearer_id != 0 {
                    if item.erab == Some(Ok(())) {
                        release.push(item.ebi);
                    }
                    remove_bearer(ctx, item.bearer_id);
                }
            }
        }
        contexts.push(bc);
    }
    let cause = match (set_up, first_failure) {
        (0, Some(c)) => c,
        (_, Some(_)) => GtpCause::RequestAcceptedPartially,
        _ => GtpCause::RequestAccepted,
    };
    rsp.add_ie(Gtp2CauseIe::new(cause as u8).to_ie(0));
    for bc in &contexts {
        rsp.add_bearer_context(0, bc);
    }
    release_erabs(ctx, p.mme_ue_id, &release);
    log::info!(
        "S11 Create Bearer Response to {} (seq {}): cause {}, {set_up} of {} bearer(s) set up \
         (TS 23.401 §5.4.1 step 8)",
        p.peer,
        p.seq,
        cause as u8,
        p.items.len()
    );
    if let Err(e) = crate::gtp_path::send_response_to_sgwc(p.peer, &rsp) {
        log::error!("S11 Create Bearer Response to {} failed: {e}", p.peer);
    }
}

/// Drive T3485 (TS 24.301 §6.4.2.6): retransmit on expiry in DOWNLINK NAS TRANSPORT;
/// on the fifth expiry, or when the S1 connection is gone, the bearer fails "UE not
/// responding".
pub fn sweep(ctx: &MmeContext, now: Instant) {
    if !std::ptr::eq(ctx, crate::context::mme_self()) {
        return;
    }
    let mut resend: Vec<(u64, Vec<u8>)> = Vec::new();
    let mut done = Vec::new();
    let mut to_signal = Vec::new();
    let budget = answer_budget();
    {
        let mut list = pending();
        // #1216 review M3/M5: a parked request is settled when its UE is gone,
        // when the Attach it waited for ended without completing, or when the
        // answer budget runs out; signalled ones are cut short by the budget too.
        let mut i = 0;
        while i < list.len() {
            let p = &mut list[i];
            let ue = ctx.mme_ue_find_by_id(p.mme_ue_id);
            let late = now.saturating_duration_since(p.received) >= budget;
            let cause = match (&ue, p.parked) {
                (None, _) => Some(GtpCause::ContextNotFound),
                (Some(_), Parked::Paging) if late => Some(GtpCause::UnableToPageUe),
                (Some(_), _) if late => Some(GtpCause::UeNotResponding),
                _ => None,
            };
            if let Some(cause) = cause {
                fail_unsignalled(p, cause);
                done.push(list.remove(i));
                continue;
            }
            if p.parked == Parked::Attach && ue.as_ref().is_some_and(|u| !attach_in_progress(u)) {
                // The Attach is over (completed without the hook, or replaced):
                // signal now; `signal` refuses it if the UE has no S1 connection.
                to_signal.push(list.remove(i));
                continue;
            }
            i += 1;
        }
        for p in list.iter_mut().filter(|p| p.parked == Parked::No) {
            let connected = ctx.mme_ue_find_by_id(p.mme_ue_id).is_some_and(|ue| {
                ctx.enb_ue_find_by_id(ue.enb_ue_id)
                    .is_some_and(|e| e.mme_ue_id == p.mme_ue_id)
            });
            for item in p.items.iter_mut().filter(|i| i.outcome().is_none()) {
                if !connected {
                    item.refused = Some(GtpCause::UeNotResponding);
                } else if item.nas.is_none() && now >= item.deadline {
                    if item.retries >= T3485_RETRANSMISSIONS {
                        item.nas = Some(Err(GtpCause::UeNotResponding));
                    } else {
                        item.retries += 1;
                        item.deadline = now + T3485_DURATION;
                        resend.push((p.mme_ue_id, item.pkbuf.clone()));
                    }
                }
            }
        }
        let mut i = 0;
        while i < list.len() {
            if list[i].parked == Parked::No && list[i].items.iter().all(|it| it.outcome().is_some())
            {
                done.push(list.remove(i));
            } else {
                i += 1;
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
        log::info!(
            "UE {mme_ue_id}: T3485 expired; ACTIVATE DEDICATED EPS BEARER CONTEXT REQUEST resent"
        );
        if let Err(e) = crate::nas_path::nas_eps_send_to_downlink_nas_transport(&enb_ue, pkbuf) {
            log::error!("UE {mme_ue_id}: T3485 retransmission failed: {e}");
        }
    }
    for p in done {
        answer(ctx, &p);
    }
    for mut p in to_signal {
        signal(ctx, &mut p);
        finish_or_keep(ctx, p);
    }
}

/// Force every T3485 of `mme_ue_id` to have expired. Test-only.
#[cfg(test)]
pub(crate) fn expire_for_test(mme_ue_id: u64) {
    for p in pending().iter_mut().filter(|p| p.mme_ue_id == mme_ue_id) {
        for i in p.items.iter_mut() {
            i.deadline = Instant::now() - Duration::from_millis(1);
        }
    }
}

/// Make every activation of `mme_ue_id` `by` older. Test-only.
#[cfg(test)]
pub(crate) fn age_for_test(mme_ue_id: u64, by: Duration) {
    for p in pending().iter_mut().filter(|p| p.mme_ue_id == mme_ue_id) {
        p.received -= by;
    }
}

/// Drop every pending activation. Test-only.
#[cfg(test)]
pub(crate) fn clear_for_test() {
    pending().clear();
}
