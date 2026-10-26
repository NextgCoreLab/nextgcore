//! UE requested bearer resource allocation and modification (#1282, TS 23.401
//! §5.4.5, TS 24.301 §6.5.3 / §6.5.4).
//!
//! 1. **The UE's request.** A BEARER RESOURCE ALLOCATION REQUEST (§8.3.8) or BEARER
//!    RESOURCE MODIFICATION REQUEST (§8.3.10) is checked by the MME (§6.5.3.6,
//!    §6.5.4.6, §7.3.1):
//!    - a PTI that is unassigned (0) or reserved (255) is rejected with #81;
//!    - an allocation whose Linked EPS bearer identity is not the default bearer of
//!      an established PDN connection is rejected with #43, as is a modification
//!      whose "EPS bearer identity for packet filter" names no active bearer;
//!    - a PDN connection for emergency bearer services is rejected with #31 (an
//!      allocation) or #30 (a modification).
//!
//!    The traffic flow aggregate itself is checked by the PDN GW (§6.5.3.4 /
//!    §6.5.4.4 "checked by the network"), whose refusal comes back as a Bearer
//!    Resource Failure Indication.
//! 2. **The Command** (TS 23.401 §5.4.5 step 2, TS 29.274 §7.2.5): LBI, PTI, the TAD
//!    (the NAS traffic flow aggregate, the same TS 24.008 §10.5.6.12 coding), the
//!    Flow QoS from the Required traffic flow QoS, the EBI (instance 1) for a
//!    modification, and the UE's PCO / ePCO, copied. It goes under a Command
//!    sequence number (MSB set, §7.6), which its triggered message carries back.
//! 3. **What comes back**, matched by that number in `gtp_path`:
//!    - a Create, Update or Delete Bearer Request: carried out by
//!      `bearer_activation` / `bearer_deactivation` with the request's PTI, which is
//!      what stops the UE's T3480 / T3481 (§6.5.3.3, §6.5.4.3);
//!    - a Bearer Resource Failure Indication (§7.2.6): BEARER RESOURCE ALLOCATION /
//!      MODIFICATION REJECT with the PTI and the ESM cause of TS 29.274 Annex C Table
//!      C.1 (§5.4.5 step 5);
//!    - nothing (N3 exhausted): the same REJECT with #34 "service option temporarily
//!      out of order" (Table C.1's mapping of #100 "remote peer not responding").
//!
//! T3480 / T3481 are the UE's timers. A UE retransmission (same PTI) while the
//! Command is outstanding, or after its triggered request arrived, is not sent on
//! again: the Command retransmits on its own T3, and the triggered NAS request on
//! its T3485 / T3486 / T3495. A PTI is held for [`PTI_HOLD`] after it was answered,
//! which covers the UE's five T3480 / T3481 expiries (TS 24.301 Table 10.3.2).
//!
//! Lock order: [`PENDING`] may be held while a context pool lock is taken (the
//! Command is sent under it, so its triggered message cannot be matched before
//! its record exists), never the reverse: nothing calls into this module with a
//! pool lock held.

use std::net::SocketAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::context::MmeContext;
use crate::esm_build::EsmCause;
use crate::esm_handler::{
    BearerResourceAllocationRequestData, BearerResourceModificationRequestData, RequiredQos,
};

/// How long an answered PTI is still recognised as a retransmission: five T3480 /
/// T3481 expiries (8 s each, TS 24.301 Table 10.3.2, §6.5.3.5 a) / §6.5.4.5 a)).
pub const PTI_HOLD: Duration = Duration::from_secs(45);

/// Reserved PTI value (TS 24.007 §11.2.3.1a, TS 24.301 §7.3.1).
const PTI_RESERVED: u8 = 0xff;

/// Which NAS request a Command carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// BEARER RESOURCE ALLOCATION REQUEST (§6.5.3).
    Allocation,
    /// BEARER RESOURCE MODIFICATION REQUEST (§6.5.4).
    Modification,
}

#[derive(Debug, Clone)]
struct Pending {
    mme_ue_id: u64,
    pti: u8,
    kind: Kind,
    /// The Command's sequence number.
    seq: u32,
    /// When the Command went out, or when its triggered message came back.
    since: Instant,
    /// The triggered message arrived (or the UE was answered): only kept to
    /// recognise a retransmission of the UE's request.
    answered: bool,
}

/// The UE requests sent on as a Bearer Resource Command. Process-global like
/// `bearer_activation`'s; tests hold `gtp_path::S11_TEST_LOCK`.
static PENDING: Mutex<Vec<Pending>> = Mutex::new(Vec::new());

fn pending() -> std::sync::MutexGuard<'static, Vec<Pending>> {
    PENDING.lock().unwrap_or_else(|e| e.into_inner())
}

/// Commands waiting for their triggered message. Test/diagnostic.
pub fn outstanding_count() -> usize {
    pending().iter().filter(|p| !p.answered).count()
}

/// The ESM cause for a Bearer Resource Failure Indication's GTP cause: TS 29.274
/// Annex C Table C.1 (normative), the first NAS cause listed where it lists
/// several (NOTE 3 leaves the choice to the implementation).
pub fn esm_cause_for(gtp_cause: u8) -> EsmCause {
    match gtp_cause {
        // #64 "Context not found" (other than a non-3GPP handover).
        64 => EsmCause::InvalidEpsBearerIdentity,
        // #68 "Service not supported", #83 "Preferred PDN type not supported".
        68 | 83 => EsmCause::ServiceOptionNotSupported,
        // #72 "System failure", #91 "No memory available", #100 "Remote peer not
        // responding".
        72 | 91 | 100 => EsmCause::ServiceOptionTemporarilyOutOfOrder,
        // #73 "No resources available", #84 "All dynamic addresses are occupied",
        // #113 "APN congestion", #120 "GTP-C entity congestion".
        73 | 84 | 113 | 120 => EsmCause::InsufficientResources,
        // #74 / #75 (TFT operation) are not in Table C.1; they name the same
        // errors as #97 / #98 (TAD operation).
        74 | 97 => EsmCause::SemanticErrorInTftOperation,
        75 | 98 => EsmCause::SyntacticalErrorInTftOperation,
        76 => EsmCause::SemanticErrorsInPacketFilters,
        77 => EsmCause::SyntacticalErrorsInPacketFilters,
        78 => EsmCause::MissingOrUnknownApn,
        92 => EsmCause::UserAuthenticationFailed,
        93 => EsmCause::RequestedServiceOptionNotSubscribed,
        101 => EsmCause::CollisionWithNetworkInitiatedRequest,
        114 => EsmCause::BearerHandlingNotSupported,
        116 => EsmCause::MultiplePdnConnectionsNotAllowed,
        // #85 "UE context without TFT already activated" has no ESM cause ("NA").
        85 => EsmCause::RequestRejectedUnspecified,
        // #65, #66, #67, #69, #70, #80, #86, #89, #94, #103, #107, #112, and any
        // cause Table C.1 does not list: the Serving GW or PDN GW refused.
        _ => EsmCause::RequestRejectedByGw,
    }
}

/// Drop the records past their hold, and those of UEs that are gone.
fn purge(ctx: &MmeContext, list: &mut Vec<Pending>) {
    list.retain(|p| {
        let age = p.since.elapsed();
        let live = if p.answered {
            age < PTI_HOLD
        } else {
            // An unanswered Command ends by its triggered message or N3; this only
            // catches a record whose transaction vanished without either.
            age < PTI_HOLD * 2
        };
        live && ctx.mme_ue_find_by_id(p.mme_ue_id).is_some()
    });
}

/// The NAS reject for `kind`, sent to the UE's current S1 connection.
fn reject(ctx: &MmeContext, mme_ue_id: u64, kind: Kind, pti: u8, cause: EsmCause) {
    let Some(mme_ue) = ctx.mme_ue_find_by_id(mme_ue_id) else {
        return;
    };
    let Some(enb_ue) = ctx
        .enb_ue_find_by_id(mme_ue.enb_ue_id)
        .filter(|e| e.mme_ue_id == mme_ue_id)
    else {
        log::warn!(
            "[{}] bearer resource request PTI {pti}: no S1 connection for its REJECT ({cause:?})",
            mme_ue.imsi_bcd
        );
        return;
    };
    log::info!(
        "[{}] BEARER RESOURCE {} REJECT, PTI {pti}, ESM cause {cause:?}",
        mme_ue.imsi_bcd,
        match kind {
            Kind::Allocation => "ALLOCATION",
            Kind::Modification => "MODIFICATION",
        }
    );
    let sent = match kind {
        Kind::Allocation => crate::nas_path::nas_eps_send_bearer_resource_allocation_reject(
            ctx, &mme_ue, &enb_ue, pti, cause,
        ),
        Kind::Modification => crate::nas_path::nas_eps_send_bearer_resource_modification_reject(
            ctx, &mme_ue, &enb_ue, pti, cause,
        ),
    };
    if let Err(e) = sent {
        log::error!(
            "[{}] bearer resource REJECT not sent: {e:?}",
            mme_ue.imsi_bcd
        );
    }
}

/// The session and default-bearer EBI of `mme_ue_id`'s PDN connection holding
/// `ebi`, with whether `ebi` is that default bearer. Only an established PDN
/// connection counts: its default bearer has the Serving GW's S1-U endpoint
/// (the Create Session Response came back).
fn pdn_of(ctx: &MmeContext, mme_ue_id: u64, ebi: u8) -> Option<(crate::context::MmeSess, u8)> {
    if ebi == 0 {
        return None;
    }
    let ue = ctx.mme_ue_find_by_id(mme_ue_id)?;
    ue.sess_list
        .iter()
        .filter_map(|id| ctx.sess_find_by_id(*id))
        .find_map(|sess| {
            let bearers: Vec<_> = sess
                .bearer_list
                .iter()
                .filter_map(|b| ctx.bearer_find_by_id(*b))
                .collect();
            let default = bearers.first()?;
            if default.sgw_s1u_teid == 0 {
                return None;
            }
            let lbi = default.ebi;
            bearers
                .iter()
                .any(|b| b.ebi == ebi)
                .then_some((sess.clone(), lbi))
        })
}

/// TS 24.301 Table 9.9.4.14.1: request type "emergency" (4) or "handover of
/// emergency bearer services" (6).
fn is_emergency(sess: &crate::context::MmeSess) -> bool {
    matches!(sess.ue_request_type, 4 | 6)
}

fn flow_qos(q: &RequiredQos) -> crate::s11_build::Gtp2BearerQos {
    crate::s11_build::Gtp2BearerQos {
        qci: q.qci,
        ul_mbr: q.mbr_ul,
        dl_mbr: q.mbr_dl,
        ul_gbr: q.gbr_ul,
        dl_gbr: q.gbr_dl,
        ..Default::default()
    }
}

/// What the Command is built from, common to both requests.
struct Request<'a> {
    kind: Kind,
    pti: u8,
    /// The EBI the UE named: the Linked EBI (allocation) or the EBI for packet
    /// filter (modification).
    ebi: u8,
    tad: &'a [u8],
    qos: Option<&'a RequiredQos>,
    pco: Option<&'a [u8]>,
    epco: Option<&'a [u8]>,
}

fn on_request(ctx: &MmeContext, mme_ue_id: u64, r: Request<'_>) {
    let imsi = ctx
        .mme_ue_find_by_id(mme_ue_id)
        .map(|u| u.imsi_bcd)
        .unwrap_or_default();
    // §7.3.1 c) / d).
    if r.pti == crate::esm_build::PTI_UNASSIGNED || r.pti == PTI_RESERVED {
        log::warn!("[{imsi}] bearer resource request with PTI {}: #81", r.pti);
        // The REJECT cannot carry an unassigned PTI (the UE ignores it, §7.3.1 c),
        // and `nas_path` refuses to build one); a reserved one is sent back as is.
        if r.pti == PTI_RESERVED {
            reject(ctx, mme_ue_id, r.kind, r.pti, EsmCause::InvalidPtiValue);
        }
        return;
    }
    {
        let mut list = pending();
        purge(ctx, &mut list);
        if list
            .iter()
            .any(|p| p.mme_ue_id == mme_ue_id && p.pti == r.pti && p.kind == r.kind)
        {
            log::info!(
                "[{imsi}] bearer resource request PTI {} is a retransmission: its procedure \
                 is running",
                r.pti
            );
            return;
        }
    }
    let Some((sess, lbi)) = pdn_of(ctx, mme_ue_id, r.ebi) else {
        // §6.5.3.6 a), §6.5.4.6 a).
        log::warn!(
            "[{imsi}] bearer resource request PTI {}: EBI {} is no active bearer: #43",
            r.pti,
            r.ebi
        );
        reject(
            ctx,
            mme_ue_id,
            r.kind,
            r.pti,
            EsmCause::InvalidEpsBearerIdentity,
        );
        return;
    };
    if r.kind == Kind::Allocation && lbi != r.ebi {
        log::warn!(
            "[{imsi}] BEARER RESOURCE ALLOCATION REQUEST PTI {}: linked EBI {} is not a default \
             bearer: #43",
            r.pti,
            r.ebi
        );
        reject(
            ctx,
            mme_ue_id,
            r.kind,
            r.pti,
            EsmCause::InvalidEpsBearerIdentity,
        );
        return;
    }
    if is_emergency(&sess) {
        // §6.5.3.6 b) / §6.5.4.6 b).
        let cause = match r.kind {
            Kind::Allocation => EsmCause::RequestRejectedUnspecified,
            Kind::Modification => EsmCause::RequestRejectedByGw,
        };
        reject(ctx, mme_ue_id, r.kind, r.pti, cause);
        return;
    }
    let qos = r.qos.map(flow_qos);
    let params = crate::s11_build::BearerResourceCommandParams {
        linked_ebi: lbi,
        pti: r.pti,
        tad: r.tad,
        qos: qos.as_ref(),
        ebi: (r.kind == Kind::Modification).then_some(r.ebi),
        pco: r.pco,
        epco: r.epco,
    };
    // The record goes in before the Command does: its triggered message can come
    // back before `send_bearer_resource_command` returns. It is keyed by the number
    // the send allocates, so it is written right after, under the same lock the
    // matcher takes.
    let mut list = pending();
    match crate::gtp_path::send_bearer_resource_command(ctx, mme_ue_id, &params) {
        Ok(seq) => {
            log::info!(
                "[{imsi}] Bearer Resource Command (LBI {lbi}, PTI {}, EBI {:?}) to the SGW, seq \
                 {seq:#x}",
                r.pti,
                params.ebi
            );
            list.push(Pending {
                mme_ue_id,
                pti: r.pti,
                kind: r.kind,
                seq,
                since: Instant::now(),
                answered: false,
            });
        }
        Err(e) => {
            drop(list);
            log::error!(
                "[{imsi}] Bearer Resource Command not sent ({e}): #34 to the UE (PTI {})",
                r.pti
            );
            reject(
                ctx,
                mme_ue_id,
                r.kind,
                r.pti,
                EsmCause::ServiceOptionTemporarilyOutOfOrder,
            );
        }
    }
}

/// The UE's BEARER RESOURCE ALLOCATION REQUEST (§6.5.3.2), parsed.
pub fn on_allocation_request(
    ctx: &MmeContext,
    mme_ue_id: u64,
    pti: u8,
    req: &BearerResourceAllocationRequestData,
) {
    on_request(
        ctx,
        mme_ue_id,
        Request {
            kind: Kind::Allocation,
            pti,
            ebi: req.linked_ebi,
            tad: &req.tfa,
            qos: req.required_qos.as_ref(),
            pco: req.pco.as_deref(),
            epco: req.epco.as_deref(),
        },
    );
}

/// The UE's BEARER RESOURCE MODIFICATION REQUEST (§6.5.4.2), parsed.
pub fn on_modification_request(
    ctx: &MmeContext,
    mme_ue_id: u64,
    pti: u8,
    req: &BearerResourceModificationRequestData,
) {
    on_request(
        ctx,
        mme_ue_id,
        Request {
            kind: Kind::Modification,
            pti,
            ebi: req.ebi_for_pf,
            tad: &req.tfa,
            qos: req.required_qos.as_ref(),
            pco: req.pco.as_deref(),
            epco: req.epco.as_deref(),
        },
    );
}

/// A malformed request the parser refused: the reject the UE is owed (§6.5.3.4 /
/// §6.5.4.4, protocol errors #95-#111). `pti` as received.
pub fn on_malformed(ctx: &MmeContext, mme_ue_id: u64, kind: Kind, pti: u8) {
    if pti == crate::esm_build::PTI_UNASSIGNED {
        return;
    }
    let cause = if pti == PTI_RESERVED {
        EsmCause::InvalidPtiValue
    } else {
        EsmCause::InvalidMandatoryInformation
    };
    reject(ctx, mme_ue_id, kind, pti, cause);
}

/// The Command at `seq` was answered by its triggered Create, Update or Delete
/// Bearer Request, which carries the UE's PTI on: the request is answered.
pub fn on_triggered(seq: u32) {
    let mut list = pending();
    for p in list.iter_mut().filter(|p| p.seq == seq && !p.answered) {
        log::debug!(
            "Bearer Resource Command {seq:#x} (PTI {}) answered by its triggered request",
            p.pti
        );
        p.answered = true;
        p.since = Instant::now();
    }
}

/// Take the outstanding Command at `seq`.
fn take(seq: u32) -> Option<Pending> {
    let mut list = pending();
    let p = list.iter_mut().find(|p| p.seq == seq && !p.answered)?;
    p.answered = true;
    p.since = Instant::now();
    Some(p.clone())
}

/// A Bearer Resource Failure Indication for the Command at `seq` (TS 29.274
/// §7.2.6): the UE's request is rejected with the mapped ESM cause.
pub fn on_failure_indication(raw: &[u8], seq: u32, peer: SocketAddr) {
    let ctx = crate::context::mme_self();
    let mut bytes = bytes::Bytes::copy_from_slice(raw);
    let msg = nextgcore_gtp::v2::Gtp2Message::decode(&mut bytes).ok();
    let ie = |t: nextgcore_gtp::v2::Gtp2IeType| {
        msg.as_ref()
            .and_then(|m| m.get_ie(t as u8, 0))
            .and_then(|ie| ie.value.first().copied())
    };
    let cause = ie(nextgcore_gtp::v2::Gtp2IeType::Cause);
    let Some(p) = take(seq) else {
        log::warn!(
            "S11 Bearer Resource Failure Indication seq={seq:#x} from {peer} (cause {cause:?}) \
             answers no UE request"
        );
        return;
    };
    if let Some(pti) = ie(nextgcore_gtp::v2::Gtp2IeType::Pti).filter(|pti| *pti != p.pti) {
        log::warn!(
            "S11 Bearer Resource Failure Indication seq={seq:#x}: PTI {pti}, the Command's was \
             {}; the Command's is answered",
            p.pti
        );
    }
    // Cause is M (Table 7.2.6-1); without it the refusal is still a refusal.
    let esm = cause.map_or(EsmCause::RequestRejectedByGw, esm_cause_for);
    log::info!(
        "S11 Bearer Resource Failure Indication seq={seq:#x} from {peer}: GTP cause {cause:?} -> \
         ESM cause {esm:?} (TS 29.274 Annex C)"
    );
    reject(ctx, p.mme_ue_id, p.kind, p.pti, esm);
}

/// The Command at `seq` ran out N3 (TS 29.274 §7.6): #34, Table C.1's mapping of
/// "remote peer not responding".
pub fn on_command_unanswered(seq: u32) {
    let Some(p) = take(seq) else {
        return;
    };
    reject(
        crate::context::mme_self(),
        p.mme_ue_id,
        p.kind,
        p.pti,
        EsmCause::ServiceOptionTemporarilyOutOfOrder,
    );
}

#[cfg(test)]
pub(crate) fn clear_for_test() {
    pending().clear();
}

#[cfg(test)]
mod tests {
    use super::*;

    /// TS 29.274 Annex C Table C.1, as literals from the spec.
    #[test]
    fn failure_causes_map_as_annex_c_table_c1_says() {
        for (gtp, esm) in [
            (64, 43),
            (65, 30),
            (68, 32),
            (72, 34),
            (73, 26),
            (76, 44),
            (77, 45),
            (89, 30),
            (94, 30),
            (97, 41),
            (98, 42),
            (100, 34),
            (101, 56),
            (114, 60),
        ] {
            assert_eq!(esm_cause_for(gtp) as u8, esm, "GTP cause #{gtp}");
        }
    }
}
