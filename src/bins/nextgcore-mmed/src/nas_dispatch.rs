//! Uplink NAS dispatch (issue #43, TS 36.413 §8.6 / TS 24.301).
//!
//! ## Why this module exists
//!
//! `s1ap_handler` received `INITIAL UE MESSAGE` and `UPLINK NAS TRANSPORT`,
//! logged `nas_pdu.len()`, and dropped the PDU. Every EMM/ESM procedure entry
//! point — and `nas_security::nas_eps_security_decode` — therefore had no
//! non-test caller: ~1900 lines of parsing that no eNB could reach. This module
//! is the missing link between the S1AP layer and those handlers.
//!
//! ## Model
//!
//! One synchronous entry point, [`nas_eps_handle_uplink`]:
//!
//! 1. resolve the `MmeUe` the PDU belongs to (S-TMSI, the S1 connection's
//!    existing association, or a fresh context);
//! 2. split the NAS header, and run security-protected messages through
//!    `nas_eps_security_decode`, discarding on MAC failure
//!    (TS 24.301 §4.4.4.3);
//! 3. dispatch by EMM/ESM message type into `emm_handler` / `esm_handler` and
//!    take the spec-defined next action.
//!
//! Downlink responses are *not* returned to the caller: they go out through the
//! `nas_path` senders, which build the message, apply NAS security, wrap it in
//! `DOWNLINK NAS TRANSPORT` and push onto the S1AP send queue that
//! `S1apServer::poll_once` drains (issue #42). `Vec<S1apSend>` stays reserved
//! for *S1AP-level* responses such as Error Indication, so the layering holds:
//! S1AP errors in `s1ap_handler`, NAS in here.
//!
//! ## Locking
//!
//! The EMM handlers take `&mut MmeUe`, so they run while the `mme_ue_pool`
//! write lock is held — the same shape `s6a_handler::mme_s6a_process_inbound`
//! already uses. `nas_path`, `emm_handler` and `esm_handler` never touch
//! `MmeContext`, so nothing re-enters the pool from under that lock. Anything
//! that *does* need `MmeContext` (index maintenance, session creation, the ESM
//! hand-off) runs after the guard is dropped; `std::sync::RwLock` is not
//! reentrant, so mixing the two would deadlock.
//!
//! ## Where the procedures stop
//!
//! Authentication needs a vector from the HSS over S6a, and mmed's S6a peer is
//! never connected (`mme_fd_connect` has no caller, and mmed parses no config so
//! it has no HSS address). Bearer setup needs S11 towards the SGW (#51). Those
//! boundaries are logged where they are reached rather than papered over with
//! invented vectors or a queue nothing services.

use crate::context::{
    EnbUe, EpsGuti, MmeContext, MmeEpsType, MmeUe, S1apCauseGroup, UeCtxRelAction,
    NEXTGCORE_INVALID_POOL_ID,
};
use crate::emm_build::{EmmCause, NAS_PROTOCOL_DISCRIMINATOR_EMM, NAS_PROTOCOL_DISCRIMINATOR_ESM};
use crate::emm_handler;
use crate::esm_build::{CreateAction, EsmCause};
use crate::esm_handler;
use crate::gtp_path;
use crate::nas_path::{self, GtpCreateAction};
// #329: `s11_build`'s create action is a THIRD enum with the same purpose as
// `esm_build::CreateAction` and `nas_path::GtpCreateAction`. Aliased rather than
// imported bare so the three cannot be confused at a glance in this file.
use crate::nas_security::{self, SecurityHeaderTypeFlags};
use crate::s11_build::GtpCreateAction as S11CreateAction;
use crate::s1ap_build::{self, nas_cause};
use crate::s1ap_path;

/// EMM message types as constants usable in `match` patterns.
///
/// Derived from [`crate::emm_build::NasEpsMessageType`] so the wire values are
/// stated once; `as` casts are not allowed in patterns, but const paths are.
mod emm_type {
    use crate::emm_build::NasEpsMessageType as T;

    pub const ATTACH_REQUEST: u8 = T::AttachRequest as u8;
    pub const ATTACH_COMPLETE: u8 = T::AttachComplete as u8;
    pub const DETACH_REQUEST: u8 = T::DetachRequest as u8;
    pub const DETACH_ACCEPT: u8 = T::DetachAccept as u8;
    pub const TAU_REQUEST: u8 = T::TauRequest as u8;
    pub const TAU_COMPLETE: u8 = T::TauComplete as u8;
    pub const EXTENDED_SERVICE_REQUEST: u8 = T::ExtendedServiceRequest as u8;
    pub const GUTI_REALLOCATION_COMPLETE: u8 = T::GutiReallocationComplete as u8;
    pub const AUTHENTICATION_RESPONSE: u8 = T::AuthenticationResponse as u8;
    pub const AUTHENTICATION_FAILURE: u8 = T::AuthenticationFailure as u8;
    pub const IDENTITY_RESPONSE: u8 = T::IdentityResponse as u8;
    pub const SECURITY_MODE_COMPLETE: u8 = T::SecurityModeComplete as u8;
    pub const SECURITY_MODE_REJECT: u8 = T::SecurityModeReject as u8;
    pub const EMM_STATUS: u8 = T::EmmStatus as u8;
    pub const UPLINK_NAS_TRANSPORT: u8 = T::UplinkNasTransport as u8;
}

/// ESM message types as constants usable in `match` patterns.
mod esm_type {
    use crate::esm_build::EsmMessageType as T;

    pub const ACTIVATE_DEFAULT_BEARER_ACCEPT: u8 = T::ActivateDefaultEpsBearerContextAccept as u8;
    pub const ACTIVATE_DEFAULT_BEARER_REJECT: u8 = T::ActivateDefaultEpsBearerContextReject as u8;
    pub const ACTIVATE_DEDICATED_BEARER_ACCEPT: u8 =
        T::ActivateDedicatedEpsBearerContextAccept as u8;
    pub const ACTIVATE_DEDICATED_BEARER_REJECT: u8 =
        T::ActivateDedicatedEpsBearerContextReject as u8;
    pub const MODIFY_BEARER_ACCEPT: u8 = T::ModifyEpsBearerContextAccept as u8;
    pub const MODIFY_BEARER_REJECT: u8 = T::ModifyEpsBearerContextReject as u8;
    pub const DEACTIVATE_BEARER_ACCEPT: u8 = T::DeactivateEpsBearerContextAccept as u8;
    pub const PDN_CONNECTIVITY_REQUEST: u8 = T::PdnConnectivityRequest as u8;
    pub const PDN_DISCONNECT_REQUEST: u8 = T::PdnDisconnectRequest as u8;
    pub const BEARER_RESOURCE_ALLOCATION_REQUEST: u8 = T::BearerResourceAllocationRequest as u8;
    pub const BEARER_RESOURCE_MODIFICATION_REQUEST: u8 = T::BearerResourceModificationRequest as u8;
    pub const ESM_INFORMATION_RESPONSE: u8 = T::EsmInformationResponse as u8;
    pub const NOTIFICATION: u8 = T::Notification as u8;
    pub const ESM_STATUS: u8 = T::EsmStatus as u8;
}

/// Security header type value that identifies a `SERVICE REQUEST`.
///
/// TS 24.301 §9.3.1: the value 12 in the security-header-type field *is* the
/// message identity — a SERVICE REQUEST carries no message-type octet. Values
/// 13-15 are unused by this version of the protocol and, per the same clause,
/// are interpreted as 12, so the dispatch compares with `>=`.
const SERVICE_REQUEST_HEADER_TYPE: u8 = 12;

/// An uplink NAS delivery surfaced by the S1AP layer (TS 36.413 §8.6.2).
#[derive(Debug, Clone, Copy)]
pub struct UplinkNas<'a> {
    /// eNB UE pool id owning the S1 connection the PDU arrived on.
    pub enb_ue_id: u64,
    /// Contents of the `NAS-PDU` IE.
    pub nas_pdu: &'a [u8],
    /// S-TMSI `(MME code, M-TMSI)` from `INITIAL UE MESSAGE`, when present.
    pub s_tmsi: Option<(u8, u32)>,
}

/// Deliver an uplink NAS PDU to the EMM/ESM layer.
pub fn nas_eps_handle_uplink(ctx: &MmeContext, uplink: UplinkNas<'_>) {
    let Some(enb_ue) = ctx.enb_ue_find_by_id(uplink.enb_ue_id) else {
        log::warn!("Uplink NAS for unknown eNB UE context {}", uplink.enb_ue_id);
        return;
    };

    // Protocol discriminator + either a message type or a security header:
    // every EPS NAS message is at least two octets (TS 24.301 §9).
    if uplink.nas_pdu.len() < 2 {
        log::warn!(
            "Uplink NAS from enb_ue_s1ap_id={} too short ({} bytes)",
            enb_ue.enb_ue_s1ap_id,
            uplink.nas_pdu.len()
        );
        return;
    }

    let Some(mme_ue_id) = resolve_mme_ue(ctx, &enb_ue, uplink.s_tmsi) else {
        return;
    };

    match uplink.nas_pdu[0] & 0x0f {
        // Every security-protected NAS message carries the EMM protocol
        // discriminator in its outer header (TS 24.301 §9.3), whatever the inner
        // message is, so this is also the entry point for protected ESM.
        NAS_PROTOCOL_DISCRIMINATOR_EMM => dispatch_emm(ctx, &enb_ue, mme_ue_id, uplink.nas_pdu),
        NAS_PROTOCOL_DISCRIMINATOR_ESM => {
            // A standalone ESM message with no security header. TS 24.301
            // §4.4.4.2 forbids forwarding unprotected messages to the ESM
            // entity; the one legitimate unprotected ESM message is the
            // container piggybacked on ATTACH REQUEST, which is held on the UE
            // context and replayed once security is established.
            log::warn!(
                "Unprotected standalone ESM message from enb_ue_s1ap_id={} discarded (TS 24.301 \
                 4.4.4.2)",
                enb_ue.enb_ue_s1ap_id
            );
        }
        other => log::warn!(
            "Uplink NAS with unknown protocol discriminator 0x{other:02x} discarded \
             (enb_ue_s1ap_id={})",
            enb_ue.enb_ue_s1ap_id
        ),
    }
}

// ============================================================================
// UE context resolution
// ============================================================================

/// Find the `MmeUe` this PDU belongs to, creating one if the S1 connection has
/// no UE context yet.
fn resolve_mme_ue(ctx: &MmeContext, enb_ue: &EnbUe, s_tmsi: Option<(u8, u32)>) -> Option<u64> {
    // An established S1 connection already names its UE context.
    if enb_ue.mme_ue_id != NEXTGCORE_INVALID_POOL_ID
        && ctx.mme_ue_find_by_id(enb_ue.mme_ue_id).is_some()
    {
        return Some(enb_ue.mme_ue_id);
    }

    // TS 36.413 §9.2.3.6: the eNB echoes the S-TMSI the UE used, which lets the
    // MME recover the context for a Service Request or paging response instead
    // of treating the UE as new.
    //
    // `current.m_tmsi` is the GUTI committed at ATTACH COMPLETE / TAU COMPLETE
    // / GUTI REALLOCATION COMPLETE (#46, #956).
    if let Some((mme_code, m_tmsi)) = s_tmsi {
        if let Some(mme_ue_id) = ctx.mme_ue_find_by_s_tmsi(mme_code, m_tmsi) {
            log::info!(
                "S-TMSI (mmec={mme_code}, m_tmsi=0x{m_tmsi:08x}) re-associated with UE context \
                 {mme_ue_id}"
            );
            ctx.enb_ue_associate_mme_ue(enb_ue.id, mme_ue_id);
            return Some(mme_ue_id);
        }
        log::debug!(
            "S-TMSI (mmec={mme_code}, m_tmsi=0x{m_tmsi:08x}) matches no UE context; \
             treating the UE as new"
        );
    }

    let mme_ue_id = ctx.mme_ue_add(enb_ue.id);
    ctx.enb_ue_associate_mme_ue(enb_ue.id, mme_ue_id);
    log::debug!(
        "Created UE context {mme_ue_id} for enb_ue_s1ap_id={}",
        enb_ue.enb_ue_s1ap_id
    );
    Some(mme_ue_id)
}

// ============================================================================
// EMM dispatch
// ============================================================================

/// Whether an EMM message may be processed without integrity protection.
///
/// TS 24.301 §4.4.4.2 lists the messages the MME accepts before a NAS security
/// context exists — the ones a UE legitimately has no key for. Everything else
/// must arrive integrity protected, so a plain copy is discarded (§4.4.4.3).
/// SECURITY MODE COMPLETE is deliberately absent: it is always protected with
/// the new context the Security Mode Command established.
fn may_be_sent_unprotected(message_type: u8) -> bool {
    matches!(
        message_type,
        emm_type::ATTACH_REQUEST
            | emm_type::IDENTITY_RESPONSE
            | emm_type::AUTHENTICATION_RESPONSE
            | emm_type::AUTHENTICATION_FAILURE
            | emm_type::SECURITY_MODE_REJECT
            | emm_type::DETACH_REQUEST
            | emm_type::DETACH_ACCEPT
            | emm_type::TAU_REQUEST
    )
}

/// The plain EMM message inside an integrity-protected (not ciphered) NAS PDU,
/// when it is one TS 24.301 §4.4.4.3 lets the MME process without a secure
/// exchange. `None` for a ciphered PDU (its body cannot be read), a truncated
/// one, or a message outside that list.
///
/// Layout (§9.1): octet 1 security header type + PD, octets 2–5 MAC, octet 6
/// sequence number, then the plain NAS message.
fn unverifiable_but_processable(security_header_type: u8, pdu: &[u8]) -> Option<Vec<u8>> {
    // Header types 1 and 3 are integrity protected only; 2 and 4 are ciphered.
    if !matches!(security_header_type, 1 | 3) || pdu.len() < 8 {
        return None;
    }
    let plain = &pdu[6..];
    (plain[0] == NAS_PROTOCOL_DISCRIMINATOR_EMM && may_be_sent_unprotected(plain[1]))
        .then(|| plain.to_vec())
}

fn dispatch_emm(ctx: &MmeContext, enb_ue: &EnbUe, mme_ue_id: u64, pdu: &[u8]) {
    let security_header_type = pdu[0] >> 4;

    if security_header_type >= SERVICE_REQUEST_HEADER_TYPE {
        // TS 24.301 §5.5.2.3.5 f (#732): a pending network-initiated detach is
        // progressed over a SERVICE REQUEST.
        if crate::network_detach::on_colliding_procedure(
            ctx,
            mme_ue_id,
            crate::network_detach::CollidingProcedure::ServiceRequest,
        ) == crate::network_detach::Collision::Ignore
        {
            return;
        }
        emm_service_request(ctx, enb_ue, mme_ue_id, pdu);
        return;
    }

    let (plain, integrity_verified) = if security_header_type == 0 {
        // TS 24.301 §4.4.4.2: outside an enumerated allowlist, an EMM message
        // that is not integrity protected must not be processed, nor forwarded
        // to the ESM entity.
        if !may_be_sent_unprotected(pdu[1]) {
            log::warn!(
                "Unprotected EMM message type 0x{:02x} from enb_ue_s1ap_id={} discarded: it is \
                 not in the TS 24.301 4.4.4.2 allowlist",
                pdu[1],
                enb_ue.enb_ue_s1ap_id
            );
            return;
        }
        (pdu.to_vec(), false)
    } else {
        match decode_protected(ctx, mme_ue_id, security_header_type, pdu) {
            Some(decoded) => decoded,
            None => return,
        }
    };

    if plain.len() < 2 {
        log::warn!("Decoded EMM message too short ({} bytes)", plain.len());
        return;
    }

    // What came out of the security container: an EMM message, an ESM message,
    // or — when no algorithm was in use, so `nas_eps_security_decode` left the
    // 6-octet header attached — the protected message itself. A plain EMM
    // header is exactly 0x07 (security header type 0, PD 7), an inner ESM
    // message has PD 2 in its low nibble, and an unstripped header keeps PD 7
    // with a non-zero security-header-type nibble.
    match plain[0] & 0x0f {
        NAS_PROTOCOL_DISCRIMINATOR_ESM => {
            let Some(mme_ue) = ctx.mme_ue_find_by_id(mme_ue_id) else {
                return;
            };
            handle_esm_message(ctx, enb_ue, &mme_ue, &plain);
            return;
        }
        NAS_PROTOCOL_DISCRIMINATOR_EMM if plain[0] == NAS_PROTOCOL_DISCRIMINATOR_EMM => {}
        _ => {
            log::warn!(
                "NAS security decode left a protected message (first octet {:#04x}) from \
                 enb_ue_s1ap_id={}; discarded",
                plain[0],
                enb_ue.enb_ue_s1ap_id
            );
            return;
        }
    }

    let message_type = plain[1];
    let body = &plain[2..];

    // TS 24.301 §5.5.2.3.5 d-f (#732): an ATTACH, TAU or SERVICE REQUEST
    // arriving while a network-initiated detach is pending either aborts that
    // detach or is ignored, by the detach type.
    let colliding = match message_type {
        emm_type::ATTACH_REQUEST => Some(crate::network_detach::CollidingProcedure::Attach),
        emm_type::TAU_REQUEST => {
            Some(crate::network_detach::CollidingProcedure::TrackingAreaUpdate)
        }
        // §9.9.3.27: service type, low nibble of the first octet. 8-11 are
        // packet services; 0-4 (and the unused 5-7) are CS fallback, which also
        // must not take over the UE while it is being detached (#828).
        emm_type::EXTENDED_SERVICE_REQUEST => Some(match body.first() {
            Some(o) if (o & 0x0f) >= 8 => crate::network_detach::CollidingProcedure::ServiceRequest,
            _ => crate::network_detach::CollidingProcedure::CsFallbackServiceRequest,
        }),
        _ => None,
    };
    if let Some(procedure) = colliding {
        if crate::network_detach::on_colliding_procedure(ctx, mme_ue_id, procedure)
            == crate::network_detach::Collision::Ignore
        {
            return;
        }
    }

    match message_type {
        emm_type::ATTACH_REQUEST => emm_attach_request(ctx, enb_ue, mme_ue_id, body),
        emm_type::ATTACH_COMPLETE => emm_attach_complete(ctx, enb_ue, mme_ue_id, body),
        emm_type::IDENTITY_RESPONSE => emm_identity_response(ctx, enb_ue, mme_ue_id, body),
        emm_type::AUTHENTICATION_RESPONSE => {
            emm_authentication_response(ctx, enb_ue, mme_ue_id, body);
        }
        emm_type::SECURITY_MODE_COMPLETE => {
            emm_security_mode_complete(ctx, enb_ue, mme_ue_id, body);
        }
        // The whole decoded PDU travels alongside the body: an inter-system TAU must be
        // forwarded to the old AMF **verbatim** in the Complete TAU Request Message IE,
        // because the AMF integrity-checks those exact octets (TS 29.274 Table 7.3.5-1,
        // `29274-j60.txt:19759`). Re-encoding the body from the parsed fields would fail
        // that check and the UE would be refused (#347).
        emm_type::TAU_REQUEST => {
            emm_tau_request(ctx, enb_ue, mme_ue_id, body, &plain, integrity_verified)
        }
        emm_type::EXTENDED_SERVICE_REQUEST => {
            emm_extended_service_request(ctx, enb_ue, mme_ue_id, body);
        }
        emm_type::DETACH_REQUEST => emm_detach_request(ctx, enb_ue, mme_ue_id, body),
        emm_type::AUTHENTICATION_FAILURE => {
            emm_authentication_failure(ctx, enb_ue, mme_ue_id, body);
        }
        emm_type::SECURITY_MODE_REJECT => {
            // TS 24.301 §5.4.3.5: the network aborts the procedure and releases
            // the NAS signalling connection.
            log::error!(
                "Security Mode Reject from enb_ue_s1ap_id={} (EMM cause #{}); aborting the \
                 security mode control procedure",
                enb_ue.enb_ue_s1ap_id,
                body.first().copied().unwrap_or(0)
            );
            if let Some(mme_ue) = ctx.mme_ue_pool.write().unwrap().get_mut(&mme_ue_id) {
                mme_ue.t3460.stop();
            }
            release_ue_context(ctx, enb_ue);
        }
        emm_type::DETACH_ACCEPT => {
            // TS 24.301 §5.5.2.3.2: DETACH ACCEPT completes a network-initiated
            // detach. T3422 stops and the UE is EMM-DEREGISTERED, so its context
            // goes with the S1 connection (#688).
            if let Some(mme_ue) = ctx.mme_ue_pool.write().unwrap().get_mut(&mme_ue_id) {
                mme_ue.t3422.stop();
            }
            let deregistered = crate::network_detach::complete_mme_initiated_detach(ctx, mme_ue_id);
            log::info!(
                "Detach Accept from enb_ue_s1ap_id={}; releasing the S1 connection{}",
                enb_ue.enb_ue_s1ap_id,
                if deregistered {
                    " (network-initiated detach complete, UE context removed)"
                } else {
                    ""
                }
            );
            release_ue_context(ctx, enb_ue);
        }
        emm_type::TAU_COMPLETE => {
            log::debug!("TAU Complete from enb_ue_s1ap_id={}", enb_ue.enb_ue_s1ap_id);
            // TS 24.301 §5.5.3.2.4: the TAU procedure completed (issue #45).
            if let Some(mme_ue) = ctx.mme_ue_pool.write().unwrap().get_mut(&mme_ue_id) {
                mme_ue.t3450.stop();
            }
            // The GUTI the accept carried is now the UE's (#46). Committed HERE and
            // not at send time: until the UE acknowledges, it still answers to the
            // old identity, and promoting early would make `mme_ue_find_by_s_tmsi`
            // miss a UE that returns before the accept arrives.
            ctx.commit_staged_guti(mme_ue_id);
        }
        emm_type::GUTI_REALLOCATION_COMPLETE => {
            log::debug!(
                "GUTI Reallocation Complete from enb_ue_s1ap_id={}",
                enb_ue.enb_ue_s1ap_id
            );
            // TS 24.301 §5.4.1.3: the reallocation completed, so T3450 stops and the
            // new GUTI takes effect. Split from the TAU arm by #46 because the two
            // procedures are different and sharing an arm hid that neither committed
            // anything.
            if let Some(mme_ue) = ctx.mme_ue_pool.write().unwrap().get_mut(&mme_ue_id) {
                mme_ue.t3450.stop();
            }
            if ctx.commit_staged_guti(mme_ue_id) {
                log::info!("GUTI reallocation completed for mme_ue_id={mme_ue_id}");
            } else {
                log::warn!(
                    "GUTI Reallocation Complete for mme_ue_id={mme_ue_id} with no staged GUTI: \
                     the UE acknowledged an identity this MME did not allocate"
                );
            }
        }
        emm_type::EMM_STATUS => {
            log::warn!(
                "EMM Status from enb_ue_s1ap_id={}: cause #{}",
                enb_ue.enb_ue_s1ap_id,
                body.first().copied().unwrap_or(0)
            );
        }
        emm_type::UPLINK_NAS_TRANSPORT => {
            // NAS transport of SMS towards the SGs/VLR interface.
            log::info!(
                "EMM Uplink NAS Transport (SMS) from enb_ue_s1ap_id={} not forwarded: SGs SMS \
                 relay is out of scope here",
                enb_ue.enb_ue_s1ap_id
            );
        }
        other => log::warn!(
            "Unhandled EMM message type 0x{other:02x} from enb_ue_s1ap_id={}",
            enb_ue.enb_ue_s1ap_id
        ),
    }
}

/// Verify and decrypt a security-protected EMM message.
///
/// Returns the plain NAS message, or `None` when the message must be discarded.
/// The plain message of a security-protected PDU, and whether its integrity was
/// verified against the UE's NAS security context (#961 review: the TS 24.301
/// §4.4.4.3 messages processed without a verified MAC report `false`).
fn decode_protected(
    ctx: &MmeContext,
    mme_ue_id: u64,
    security_header_type: u8,
    pdu: &[u8],
) -> Option<(Vec<u8>, bool)> {
    let flags = SecurityHeaderTypeFlags::from_header_type(security_header_type);
    let mut message = pdu.to_vec();

    let mut pool = ctx.mme_ue_pool.write().unwrap();
    let mme_ue = pool.get_mut(&mme_ue_id)?;

    // TS 24.301 §4.4.4.2: a protected message can only be processed against an
    // existing NAS security context. `nas_eps_security_decode` answers `Ok` for
    // a context-less UE with the security header still attached, so without
    // this guard the header bytes would be misread as the message body.
    if !mme_ue.security_context_available {
        // TS 24.301 §4.4.4.3: ATTACH REQUEST and the other listed messages are
        // processed even without a secure exchange, because a UE can send them
        // protected with an EPS security context the network no longer holds
        // (e.g. it kept its context after an ATTACH REJECT). The MAC cannot be
        // verified, so the plain message is taken from behind the header and
        // processed as having failed the integrity check: for an ATTACH REQUEST
        // the MME then authenticates before going further, which the attach
        // path always does (#481). A ciphered message cannot be read without the
        // context and is still discarded.
        if let Some(plain) = unverifiable_but_processable(security_header_type, pdu) {
            log::warn!(
                "[{}] Security-protected NAS message type {:#04x} from a UE with no security \
                 context: processed without integrity verification (TS 24.301 4.4.4.3)",
                mme_ue.imsi_bcd,
                plain[1]
            );
            return Some((plain, false));
        }
        if matches!(security_header_type, 2 | 4) {
            // TS 24.301 §4.4.5: a UE ciphers only once the secure exchange is
            // established for THIS NAS signalling connection. With no context here
            // this connection has not run a SECURITY MODE CONTROL, so the UE is
            // ciphering with a context the network no longer holds (e.g. kept after
            // an ATTACH REJECT, #488). The body cannot be read; naming the cause
            // makes the UE-side fault visible instead of a bare discard.
            log::warn!(
                "[{}] CIPHERED NAS message (header type {security_header_type}) from a UE with \
                 no security context; discarded: a UE must not cipher before the secure \
                 exchange is established on this NAS signalling connection (TS 24.301 4.4.5)",
                mme_ue.imsi_bcd
            );
            return None;
        }
        log::warn!(
            "[{}] Security-protected NAS (header type {security_header_type}) from a UE with no \
             security context; discarded",
            mme_ue.imsi_bcd
        );
        return None;
    }

    let decoded = nas_security::nas_eps_security_decode(mme_ue, flags, &mut message);

    // TS 24.301 §4.4.4.3: a message that fails the integrity check is discarded.
    // The decode reports that as an error; the flag is cleared as well so it
    // cannot leak into the next message on this context.
    let mac_failed = std::mem::take(&mut mme_ue.mac_failed);
    // TS 24.301 §4.4.4.3: an ATTACH REQUEST that fails the integrity check is
    // still processed, and the MME authenticates the subscriber before going any
    // further (the attach path always does). Every other failing message is
    // discarded as before.
    if mac_failed {
        if let Some(plain) = unverifiable_but_processable(security_header_type, pdu)
            .filter(|plain| plain[1] == emm_type::ATTACH_REQUEST)
        {
            log::warn!(
                "[{}] ATTACH REQUEST failed the NAS integrity check: processed, and the \
                 subscriber will be re-authenticated (TS 24.301 4.4.4.3)",
                mme_ue.imsi_bcd
            );
            return Some((plain, false));
        }
    }
    if let Err(e) = decoded {
        log::warn!(
            "[{}] NAS security decode failed: {e} (mac_failed={mac_failed})",
            mme_ue.imsi_bcd
        );
        return None;
    }

    // EIA0 "verifies" every message: it is no integrity protection.
    let verified = !mac_failed && mme_ue.selected_int_algorithm != 0;
    Some((message, verified))
}

// ============================================================================
// EMM procedures
// ============================================================================

fn emm_attach_request(ctx: &MmeContext, enb_ue: &EnbUe, mme_ue_id: u64, body: &[u8]) {
    let parsed = {
        let mut pool = ctx.mme_ue_pool.write().unwrap();
        let Some(mme_ue) = pool.get_mut(&mme_ue_id) else {
            return;
        };
        mme_ue.nas_eps.type_ = MmeEpsType::AttachRequest;

        match emm_handler::handle_attach_request(enb_ue, mme_ue, body) {
            Ok(parsed) => {
                // TS 24.301 §5.5.1.2.2: the piggybacked ESM container is
                // processed once a security context exists, so it is held on
                // the UE context until Security Mode Complete.
                mme_ue.pdn_connectivity_request = parsed.esm_message.clone();
                parsed
            }
            Err(e) => {
                log::warn!(
                    "Attach Request from enb_ue_s1ap_id={} is malformed: {e}",
                    enb_ue.enb_ue_s1ap_id
                );
                // TS 24.301 §5.5.1.2.5: reject an Attach Request the MME cannot
                // parse rather than leaving the UE waiting on T3410.
                if let Err(e) = nas_path::nas_eps_send_attach_reject(
                    ctx,
                    enb_ue,
                    mme_ue,
                    EmmCause::InvalidMandatoryInformation,
                    None,
                ) {
                    log::error!("Attach Reject send failed: {e}");
                }
                return;
            }
        }
    };

    // A new attach: neither its ATTACH COMPLETE nor its step-23 Modify Bearer
    // Request has happened yet (#495).
    if let Ok(mut pool) = ctx.mme_ue_pool.write() {
        if let Some(ue) = pool.get_mut(&mme_ue_id) {
            ue.attach_completed = false;
            ue.attach_modify_bearer_sent = false;
        }
    }

    // TS 24.301 §9.9.3.11 attach type 3 is an EMERGENCY attach. Recorded on the
    // context so the rest of the stack can tell one from a normal attach (#46).
    //
    // What this does NOT do, stated because the difference matters: emergency BEARER
    // SERVICES are not implemented. §5.5.1.3 lets an emergency attach proceed for an
    // unauthenticated or unsubscribed UE with EIA0/NIA0 and an emergency APN, and
    // none of that exists here — so an emergency attach still goes through the normal
    // authentication and subscription path and will fail wherever that fails. The flag
    // makes the case visible instead of silently indistinguishable, and the accept's
    // EPS attach result is now correct for it (§9.9.3.10 has no emergency value, so it
    // is EPS-only).
    if parsed.attach_type == crate::emm_build::AttachType::EpsEmergencyAttach as u8 {
        if let Ok(mut pool) = ctx.mme_ue_pool.write() {
            if let Some(ue) = pool.get_mut(&mme_ue_id) {
                ue.emergency_attach = true;
            }
        }
        log::warn!(
            "EMERGENCY attach requested on enb_ue_s1ap_id={}: recognised and recorded, but \
             emergency bearer services (unauthenticated access, EIA0/NIA0, emergency APN) are \
             not implemented, so this attach follows the normal path",
            enb_ue.enb_ue_s1ap_id
        );
    }

    // Allocate the GUTI this attach will hand the UE (TS 24.301 §5.4.1). Staged in
    // `next`; promoted to `current` when the UE acknowledges. Before #46 nothing
    // allocated one, so the accepts' `next.m_tmsi.is_some()` gate was never true
    // outside tests and the GUTI IE was dead code — which also left
    // `mme_ue_find_by_s_tmsi` and the GUTI-identified attach lookup below permanently
    // dormant, as `resolve_mme_ue`'s comment said.
    if !ctx.allocate_guti(mme_ue_id) {
        log::warn!(
            "no GUTI allocated for enb_ue_s1ap_id={}: the UE will be given none and must keep \
             identifying itself by IMSI",
            enb_ue.enb_ue_s1ap_id
        );
    }

    if let Some(imsi) = parsed.imsi.as_deref() {
        log::info!(
            "Attach Request: IMSI[{imsi}] attach_type[{}] on enb_ue_s1ap_id={}",
            parsed.attach_type,
            enb_ue.enb_ue_s1ap_id
        );
        index_imsi(ctx, mme_ue_id, imsi);
        authenticate(ctx, enb_ue, mme_ue_id);
        return;
    }

    // A GUTI-identified attach only names a subscriber if the MME still holds
    // the context that GUTI was allocated from. See `resolve_mme_ue` on why
    // that lookup is dormant until #46.
    if let Some(guti) = parsed.guti.as_ref() {
        let known = ctx.mme_ue_find_by_guti(&EpsGuti {
            plmn_id: guti.plmn_id.clone(),
            mme_gid: guti.mme_gid,
            mme_code: guti.mme_code,
            m_tmsi: guti.m_tmsi,
        });
        if let Some(imsi) = known
            .filter(|id| *id != mme_ue_id)
            .and_then(|id| ctx.mme_ue_find_by_id(id))
            .map(|ue| ue.imsi_bcd)
            .filter(|imsi| !imsi.is_empty())
        {
            log::info!(
                "Attach Request: GUTI m_tmsi=0x{:08x} resolves to IMSI[{imsi}]",
                guti.m_tmsi
            );
            index_imsi(ctx, mme_ue_id, &imsi);
            authenticate(ctx, enb_ue, mme_ue_id);
            return;
        }
    }

    // TS 24.301 §5.5.1.2.3: the MME identifies the UE before it can continue.
    log::info!(
        "Attach Request without a usable identity on enb_ue_s1ap_id={}; requesting the IMSI",
        enb_ue.enb_ue_s1ap_id
    );
    request_identity(ctx, enb_ue, mme_ue_id);
}

fn emm_attach_complete(ctx: &MmeContext, enb_ue: &EnbUe, mme_ue_id: u64, body: &[u8]) {
    let esm_message = {
        let mut pool = ctx.mme_ue_pool.write().unwrap();
        let Some(mme_ue) = pool.get_mut(&mme_ue_id) else {
            return;
        };
        match emm_handler::handle_attach_complete(enb_ue, mme_ue, body) {
            Ok(esm_message) => {
                // TS 24.301 §5.5.1.2.4: the attach procedure completed, so T3450
                // stops and the stored ATTACH ACCEPT is discarded (issue #45).
                mme_ue.t3450.stop();
                mme_ue.attach_completed = true;
                esm_message
            }
            Err(e) => {
                log::warn!("[{}] Attach Complete rejected: {e}", mme_ue.imsi_bcd);
                return;
            }
        }
    };

    // TS 24.301 §5.5.1.2.4: "Upon receiving an ATTACH COMPLETE message, the MME
    // ... shall consider the GUTI sent in the ATTACH ACCEPT message as valid"
    // (#956). Without this the S-TMSI an idle UE returns with (SERVICE REQUEST,
    // paging response) matched no context, the SERVICE REQUEST could not be
    // verified, and every return from ECM-IDLE ended in a re-attach.
    ctx.commit_staged_guti(mme_ue_id);

    // TS 24.301 §5.5.1.2.4: the ESM container carries ACTIVATE DEFAULT EPS
    // BEARER CONTEXT ACCEPT, which belongs to the ESM entity.
    forward_to_esm(ctx, enb_ue, mme_ue_id, &esm_message);

    modify_bearer_after_attach(ctx, enb_ue.id, mme_ue_id);

    // #641, TS 23.401 Annex F NOTE 2: dedicated bearers held for the Attach.
    crate::bearer_activation::on_attach_complete(ctx, mme_ue_id);
}

/// TS 23.401 §5.3.2.1 step 23: once BOTH the Initial Context Setup Response (step
/// 20, which carried the eNB's S1-U F-TEID) and the ATTACH COMPLETE (step 22) have
/// arrived, send the Serving GW a Modify Bearer Request with the eNB's address and
/// TEID, so downlink user-plane data can flow. Called from both arrival points; it
/// acts once, on whichever comes second (#495).
///
/// Before #495 nothing on the attach path sent it, so the SGW never learned the
/// eNB's downlink tunnel and an attached UE had an uplink-only user plane.
pub fn modify_bearer_after_attach(ctx: &MmeContext, enb_ue_id: u64, mme_ue_id: u64) {
    let ready = {
        let Ok(pool) = ctx.mme_ue_pool.read() else {
            return;
        };
        let Some(ue) = pool.get(&mme_ue_id) else {
            return;
        };
        ue.attach_completed && !ue.attach_modify_bearer_sent
    };
    if !ready {
        return;
    }
    // Step 20 is in when every bearer of the UE has the eNB's S1-U TEID.
    let bearers = gtp_path::bearers_of_ue(ctx, mme_ue_id);
    if bearers.is_empty() || bearers.iter().any(|b| b.enb_s1u_teid == 0) {
        return;
    }
    if let Ok(mut pool) = ctx.mme_ue_pool.write() {
        if let Some(ue) = pool.get_mut(&mme_ue_id) {
            if ue.attach_modify_bearer_sent {
                return;
            }
            ue.attach_modify_bearer_sent = true;
        }
    }
    match gtp_path::send_modify_bearer_request(
        ctx,
        enb_ue_id,
        mme_ue_id,
        false,
        crate::s11_build::GtpModifyAction::NoAction,
    ) {
        Ok(_) => log::info!(
            "Attach: Modify Bearer Request sent with the eNB S1-U F-TEID (TS 23.401 §5.3.2.1 \
             step 23)"
        ),
        Err(e) => log::error!(
            "Attach: Modify Bearer Request failed: {e}. The UE is attached, but the SGW has \
             no downlink tunnel to the eNB, so downlink user-plane data is dropped"
        ),
    }
}

fn emm_identity_response(ctx: &MmeContext, enb_ue: &EnbUe, mme_ue_id: u64, body: &[u8]) {
    let imsi = {
        let mut pool = ctx.mme_ue_pool.write().unwrap();
        let Some(mme_ue) = pool.get_mut(&mme_ue_id) else {
            return;
        };
        if let Err(e) = emm_handler::handle_identity_response(enb_ue, mme_ue, body) {
            log::warn!(
                "Identity Response from enb_ue_s1ap_id={} rejected: {e}",
                enb_ue.enb_ue_s1ap_id
            );
            return;
        }
        // TS 24.301 §5.4.4.3: the identification procedure completed (issue #45).
        mme_ue.t3470.stop();
        // `handle_identity_response` writes `imsi_bcd` only for an IMSI
        // identity; an IMEI/IMEISV answer leaves it untouched.
        mme_ue.imsi_bcd.clone()
    };

    if imsi.is_empty() {
        log::warn!(
            "Identity Response on enb_ue_s1ap_id={} carried no IMSI; cannot continue the \
             procedure",
            enb_ue.enb_ue_s1ap_id
        );
        return;
    }

    index_imsi(ctx, mme_ue_id, &imsi);
    authenticate(ctx, enb_ue, mme_ue_id);
}

fn emm_authentication_response(ctx: &MmeContext, enb_ue: &EnbUe, mme_ue_id: u64, body: &[u8]) {
    let mut pool = ctx.mme_ue_pool.write().unwrap();
    let Some(mme_ue) = pool.get_mut(&mme_ue_id) else {
        return;
    };

    match emm_handler::handle_authentication_response(enb_ue, mme_ue, body) {
        Ok(true) => {
            // TS 24.301 §5.4.3.2: authentication done, take the NAS security
            // context into use. TS 33.401 §7.2.4.3: the algorithms are chosen
            // here, from the UE's advertised capabilities and the MME's ordered
            // preference, and the NAS keys are derived from KASME for exactly
            // those algorithms (Annex A.7) — so both must happen before the
            // Security Mode Command is built with them.
            let Some(selected) = nas_security::select_nas_algorithms(
                &ctx.integrity_order,
                &ctx.ciphering_order,
                &mme_ue.ue_network_capability,
            ) else {
                log::warn!(
                    "[{}] No NAS integrity algorithm in common with the UE; rejecting the attach",
                    mme_ue.imsi_bcd
                );
                if let Err(e) = nas_path::nas_eps_send_attach_reject(
                    ctx,
                    enb_ue,
                    mme_ue,
                    EmmCause::UeSecurityCapabilitiesMismatch,
                    None,
                ) {
                    log::error!("Attach Reject send failed: {e}");
                }
                return;
            };
            nas_security::derive_nas_keys(mme_ue, selected);

            // TS 24.301 §5.4.2.3 / §5.4.3.3: the procedure completed, so T3460
            // stops and its retransmission buffer goes with it (issue #45).
            mme_ue.t3460.stop();
            if let Err(e) = nas_path::nas_eps_send_security_mode_command(mme_ue, enb_ue) {
                log::error!(
                    "[{}] Security Mode Command send failed: {e}",
                    mme_ue.imsi_bcd
                );
            }
        }
        Ok(false) => {
            // TS 24.301 §5.4.2.7 (c): RES mismatch on a UE identified by IMSI
            // aborts authentication with AUTHENTICATION REJECT.
            log::warn!(
                "[{}] Authentication Response mismatch; rejecting",
                mme_ue.imsi_bcd
            );
            if let Err(e) = nas_path::nas_eps_send_authentication_reject(mme_ue, enb_ue) {
                log::error!(
                    "[{}] Authentication Reject send failed: {e}",
                    mme_ue.imsi_bcd
                );
            }
        }
        Err(e) => log::warn!(
            "[{}] Authentication Response rejected: {e}",
            mme_ue.imsi_bcd
        ),
    }
}

/// Handle AUTHENTICATION FAILURE (TS 24.301 §5.4.2.7).
fn emm_authentication_failure(ctx: &MmeContext, enb_ue: &EnbUe, mme_ue_id: u64, body: &[u8]) {
    let outcome = {
        let mut pool = ctx.mme_ue_pool.write().unwrap();
        let Some(mme_ue) = pool.get_mut(&mme_ue_id) else {
            return;
        };
        // The authentication procedure is over either way, so T3460 stops and
        // the challenge is not retransmitted.
        mme_ue.t3460.stop();

        match emm_handler::handle_authentication_failure(enb_ue, mme_ue, body) {
            Ok(outcome) => outcome,
            Err(e) => {
                log::warn!(
                    "[{}] Authentication Failure malformed: {e}; rejecting",
                    mme_ue.imsi_bcd
                );
                if let Err(e) = nas_path::nas_eps_send_authentication_reject(mme_ue, enb_ue) {
                    log::error!("Authentication Reject send failed: {e}");
                }
                return;
            }
        }
    };

    match outcome {
        emm_handler::AuthenticationFailure::SynchFailure(auts) => {
            // TS 33.401 §6.1.1: the AUTS goes to the HSS as
            // Re-synchronization-Info in a fresh AIR, and the vector it returns
            // restarts authentication. `fd_path::mme_s6a_send_air` already takes
            // the AUTS and `s6a::add_resync_info` already encodes it — what is
            // missing is the connected S6a peer, so the AUTS is stored for that
            // request rather than dropped or pretended to be sent.
            let mut pool = ctx.mme_ue_pool.write().unwrap();
            let Some(mme_ue) = pool.get_mut(&mme_ue_id) else {
                return;
            };
            mme_ue.resync_auts = Some(*auts);
            mme_ue.xres_len = 0;
            log::warn!(
                "[{}] Synch failure: AUTS stored for a re-synchronisation AIR, which needs \
                 mmed's S6a peer to be connected",
                mme_ue.imsi_bcd
            );
        }
        emm_handler::AuthenticationFailure::MacFailure => {
            // TS 24.301 §5.4.2.7 e): on MAC failure the network may re-initiate
            // the identification procedure and authenticate the UE it names,
            // which is the only branch that can make progress without the HSS.
            log::warn!("MAC failure reported for UE {mme_ue_id}; re-identifying");
            {
                // The vector the UE rejected must not be reused. `imsi_bcd` is
                // deliberately left in place: clearing it would strand the
                // context's entry in the IMSI index, which is keyed by that
                // string, and the Identity Response re-indexes it anyway.
                let mut pool = ctx.mme_ue_pool.write().unwrap();
                if let Some(mme_ue) = pool.get_mut(&mme_ue_id) {
                    mme_ue.xres_len = 0;
                }
            }
            request_identity(ctx, enb_ue, mme_ue_id);
        }
        emm_handler::AuthenticationFailure::Other(cause) => {
            // Anything else (e.g. #26 non-EPS authentication unacceptable)
            // aborts the procedure and releases the connection.
            log::warn!(
                "Authentication Failure cause #{cause} for UE {mme_ue_id}; aborting and \
                 releasing the S1 connection"
            );
            release_ue_context(ctx, enb_ue);
        }
    }
}

fn emm_security_mode_complete(ctx: &MmeContext, enb_ue: &EnbUe, mme_ue_id: u64, body: &[u8]) {
    let held_esm = {
        let mut pool = ctx.mme_ue_pool.write().unwrap();
        let Some(mme_ue) = pool.get_mut(&mme_ue_id) else {
            return;
        };
        if let Err(e) = emm_handler::handle_security_mode_complete(enb_ue, mme_ue, body) {
            log::warn!("[{}] Security Mode Complete rejected: {e}", mme_ue.imsi_bcd);
            return;
        }
        // TS 24.301 §5.4.3.3: the security mode control procedure completed, so
        // T3460 stops and the stored command is discarded (issue #45).
        mme_ue.t3460.stop();
        // Replay the container held since Attach Request, now that
        // `security_context_available` is set (TS 24.301 §5.5.1.2.2).
        std::mem::take(&mut mme_ue.pdn_connectivity_request)
    };

    // TS 23.401 §5.3.2.1 step 12: with the security context in place the MME
    // registers itself with the HSS and takes the subscription data, which is
    // what an ATTACH ACCEPT is built from. `mme_s6a_send_ulr` is async, so the
    // request goes on the same queue the AIR uses.
    if !held_esm.is_empty() {
        forward_to_esm(ctx, enb_ue, mme_ue_id, &held_esm);
    }
    request_subscription_data(ctx, mme_ue_id);
}

/// Ask the HSS to register this MME and return the subscriber's data.
fn request_subscription_data(ctx: &MmeContext, mme_ue_id: u64) {
    let Some(mme_ue) = ctx.mme_ue_find_by_id(mme_ue_id) else {
        return;
    };
    if mme_ue.num_of_session != 0 {
        // Already subscribed: a retransmitted SECURITY MODE COMPLETE must not
        // re-register with the HSS.
        return;
    }
    // ULR-Flags "initial attach indicator" (TS 29.272 §7.3.7): set for an attach
    // so the HSS cancels any previous MME's registration, clear for a TAU.
    let initial_attach = mme_ue.nas_eps.type_ == MmeEpsType::AttachRequest;
    log::info!(
        "[{}] Requesting subscription data from the HSS (initial_attach={initial_attach})",
        mme_ue.imsi_bcd
    );
    crate::fd_path::queue_update_location(mme_ue_id, initial_attach);
}

fn emm_tau_request(
    ctx: &MmeContext,
    enb_ue: &EnbUe,
    mme_ue_id: u64,
    body: &[u8],
    whole_pdu: &[u8],
    integrity_verified: bool,
) {
    let mut pool = ctx.mme_ue_pool.write().unwrap();
    let Some(mme_ue) = pool.get_mut(&mme_ue_id) else {
        return;
    };
    mme_ue.nas_eps.type_ = MmeEpsType::TauRequest;

    let parsed = match emm_handler::handle_tau_request(enb_ue, mme_ue, body) {
        Ok(parsed) => parsed,
        Err(e) => {
            log::warn!(
                "TAU Request from enb_ue_s1ap_id={} is malformed: {e}",
                enb_ue.enb_ue_s1ap_id
            );
            if let Err(e) = nas_path::nas_eps_send_tau_reject(
                enb_ue,
                mme_ue,
                EmmCause::InvalidMandatoryInformation,
            ) {
                log::error!("TAU Reject send failed: {e}");
            }
            return;
        }
    };

    // ------------------------------------------------------------------
    // Inter-system TAU: the UE has just come from 5GS (#347)
    // ------------------------------------------------------------------
    //
    // The discriminator is the UE status IE's `N1 mode reg` bit, NOT a mapped GUTI —
    // TS 24.301 §5.5.3.2.2 case z has the UE send a GUTI mapped from its 5G-GUTI while
    // typing it "Native GUTI", so the GUTI type cannot distinguish this from an
    // intra-EPS TAU. See `TauRequestData::five_gmm_registered`.
    //
    // This branch comes BEFORE the security-context check below, and that ordering is
    // load-bearing: a UE arriving from 5GS has **no EPS security context here yet** —
    // §4.4.2.2 (`24301-k00.txt:4450-4462`) has it protect the TAU REQUEST with its
    // *current 5G* context, which this MME does not hold. So the existing check would
    // reject every inter-system TAU as implicitly detached, which is exactly what
    // happens today. Obtaining that context IS this procedure.
    if parsed.five_gmm_registered {
        let Some(guti) = parsed.old_guti.as_ref().map(|g| EpsGuti {
            plmn_id: g.plmn_id.clone(),
            mme_gid: g.mme_gid,
            mme_code: g.mme_code,
            m_tmsi: g.m_tmsi,
        }) else {
            // §5.5.3.2.2 case z requires the Old GUTI IE, so a UE claiming a 5GMM
            // registration without one has given the MME nothing to ask the AMF about.
            log::warn!(
                "Inter-system TAU (UE status: 5GMM-REGISTERED) carries no Old GUTI, which \
                 TS 24.301 §5.5.3.2.2 case z requires; rejecting with EMM cause #9"
            );
            if let Err(e) = nas_path::nas_eps_send_tau_reject(
                enb_ue,
                mme_ue,
                EmmCause::UeIdentityCannotBeDerived,
            ) {
                log::error!("TAU Reject send failed: {e}");
            }
            return;
        };

        // Released before the N26 send: `send_context_request` reads the context's peer
        // list and the response path takes the same write lock to install the transferred
        // context. Holding it across the send would deadlock the moment a response arrived
        // fast enough, which on a loopback deployment is every time.
        drop(pool);

        // `ue_validated` is FALSE, and that is a stated ceiling rather than an oversight.
        //
        // TS 23.401 §5.3.3.1 step 4 defines UE Validated as "the new MME has validated the
        // integrity protection of the TAU message", and TS 24.301 §4.4.2.2
        // (`24301-k00.txt:4452-4462`) says this TAU is protected with the UE's *current 5G
        // NAS security context*. This MME holds no 5G context and cannot derive one — the
        // K_AMF lives in the AMF — so it genuinely has not validated the message, and
        // asserting MSV would ask the AMF to skip a check nobody performed. The AMF does
        // hold the key, which is why Table 7.3.5-1 has the MME forward the TAU verbatim in
        // the Complete TAU Request Message IE for the AMF to check instead.
        match crate::n26_path::send_context_request(
            ctx, mme_ue_id, enb_ue.id, &guti, whole_pdu, false,
        ) {
            Ok(seq) => {
                log::info!(
                    "Inter-system TAU from 5GS: Context Request sent to the old AMF \
                     (seq={seq}). The TAU ACCEPT waits on the Context Response \
                     (TS 23.502 §4.11.1.3.2 steps 4-6)."
                );
                // Nothing more here: the response path continues the procedure. Returning
                // rather than falling through is what stops the UE getting a TAU ACCEPT
                // before its context has arrived.
                return;
            }
            Err(e) => {
                // TS 24.301 (`24301-k00.txt:18854-18858`): *"If the UE initiated the
                // tracking area updating procedure due to inter-system change from N1 mode
                // to S1 mode, and the MME does not support N26 interface, the MME shall
                // send a TRACKING AREA UPDATE REJECT message with EMM cause value #9 'UE
                // identity cannot be derived by the network'."*
                //
                // Cause #9 and not #10 (implicitly detached), which is what the generic
                // no-context branch below would have sent: #10 tells a UE to re-attach on
                // EPS as if its EPS registration had lapsed, while #9 says the network
                // cannot derive the identity it presented — which is the true statement
                // about a 5G-GUTI this MME cannot resolve.
                log::info!(
                    "Inter-system TAU from 5GS cannot be served ({e}); rejecting with EMM \
                     cause #9 'UE identity cannot be derived by the network', as TS 24.301 \
                     requires of an MME without a usable N26 interface"
                );
                let mut pool = ctx.mme_ue_pool.write().unwrap();
                if let Some(mme_ue) = pool.get_mut(&mme_ue_id) {
                    if let Err(e) = nas_path::nas_eps_send_tau_reject(
                        enb_ue,
                        mme_ue,
                        EmmCause::UeIdentityCannotBeDerived,
                    ) {
                        log::error!("TAU Reject send failed: {e}");
                    }
                }
                return;
            }
        }
    }

    if !mme_ue.security_context_available || mme_ue.imsi_bcd.is_empty() {
        // TS 24.301 §5.5.3.2.5: with no context for the UE the MME rejects with
        // EMM cause #10, which makes the UE re-attach.
        log::info!(
            "TAU Request (update_type={}) for a UE with no established context; rejecting as \
             implicitly detached",
            parsed.update_type
        );
        if let Err(e) =
            nas_path::nas_eps_send_tau_reject(enb_ue, mme_ue, EmmCause::ImplicitlyDetached)
        {
            log::error!("TAU Reject send failed: {e}");
        }
        return;
    }

    log::info!(
        "[{}] TAU Request accepted (update_type={}, active_flag={})",
        mme_ue.imsi_bcd,
        parsed.update_type,
        parsed.active_flag
    );
    // #961 review, TS 24.301 §5.6.2.2.1: a TAU REQUEST that passed the
    // integrity check answers paging, so paging stops; when the paging was for
    // downlink data, the user plane is brought up with the TAU ACCEPT as with
    // the active flag (TS 23.401 §5.3.3.1 step 20, §5.3.4.3), so the buffered
    // downlink reaches the UE instead of a DDN Failure Indication discarding it.
    // The integrity result the dispatcher established for THIS message (#961
    // review): a plain TAU REQUEST, or one processed without a verifiable MAC,
    // answers nothing, so T3413 keeps running and no user plane is set up on a
    // K_eNB from an unverified COUNT.
    let verified = integrity_verified;
    let paged_for_data = if verified
        && (mme_ue.t3413.is_running() || mme_ue.paging.type_ != crate::context::PagingType::None)
    {
        let was = mme_ue.paging.type_;
        mme_ue.t3413.stop();
        mme_ue.paging.type_ = crate::context::PagingType::None;
        // #984 review: a paging for a deactivation parked behind it (#862)
        // needs the user plane too: its steps 4c-8 run on the ICS response.
        matches!(
            was,
            crate::context::PagingType::DownlinkDataNotification
                | crate::context::PagingType::DeleteBearer
        )
    } else {
        false
    };
    let restore_user_plane = verified && (parsed.active_flag || paged_for_data);
    // TS 24.301 §5.5.3.2.4: the TAU accept may reallocate the GUTI, and rotating it
    // on mobility is what keeps the temporary identity temporary (#46).
    ctx.allocate_guti(mme_ue_id);
    // The UE's active bearers, so the accept can carry a real EPS bearer context
    // status (#46). An empty slice was passed while S11 could establish nothing;
    // #51 gave the MME a real S11 endpoint, so a UE that has completed an attach
    // holds bearers worth reporting. Initial Context Setup is still not requested
    // from here — that is the attach path's job, and it has no caller yet (#51's
    // ceiling).
    // #993, TS 24.301 §5.5.3.2.4: the EPS bearer contexts the UE reports
    // inactive are deactivated locally, without peer-to-peer signalling to the
    // UE, and left out of the accept's status and of any Initial Context Setup.
    // The core is told after the accept (`release_lost_bearers`, below).
    let (inactive, released): (Vec<u8>, Vec<u8>) = parsed
        .eps_bearer_context_status
        .map(|status| reported_inactive(ctx, mme_ue, status))
        .unwrap_or_default();
    let bearers: Vec<crate::context::MmeBearer> = mme_ue
        .sess_list
        .iter()
        .filter_map(|sess_id| ctx.sess_find_by_id(*sess_id))
        .flat_map(|sess| {
            sess.bearer_list
                .iter()
                .filter_map(|id| ctx.bearer_find_by_id(*id))
                .collect::<Vec<_>>()
        })
        .filter(|b| !released.contains(&b.ebi))
        .collect();
    // The user plane, when it is restored: the bearers established at the
    // Serving GW, under a K_eNB from the TAU REQUEST's uplink COUNT (TS 33.401
    // §7.2.6.2, A.3). The response then sends the Modify Bearer Request
    // (`service_request_ics_pending`), as for a SERVICE REQUEST.
    let restore = restore_user_plane && bearers.iter().any(|b| b.sgw_s1u_teid != 0);
    if restore {
        mme_ue.kenb = nextgcore_crypt::kdf::nextgcore_kdf_kenb(&mme_ue.kasme, mme_ue.ul_count);
        mme_ue.nhcc = 0;
        mme_ue.nh = [0; 32];
    }
    // Every bearer the MME keeps goes in the EPS bearer context status, so the
    // UE does not delete one the MME still holds (#961 review); the Initial
    // Context Setup carries only those established at the Serving GW
    // (`nas_eps_send_tau_accept`).
    match nas_path::nas_eps_send_tau_accept(
        mme_ue,
        enb_ue,
        restore,
        &bearers,
        s1ap_build::ue_ambr_of(ctx, mme_ue),
    ) {
        Ok(()) if restore => {
            mme_ue.service_request_ics_pending = true;
            log::info!(
                "[{}] TAU Accept in an Initial Context Setup Request: user plane restored ({})",
                mme_ue.imsi_bcd,
                if paged_for_data {
                    "paging answered"
                } else {
                    "active flag"
                }
            );
        }
        Ok(()) => {}
        Err(e) => log::error!("[{}] TAU Accept send failed: {e}", mme_ue.imsi_bcd),
    }
    if !inactive.is_empty() {
        log::info!(
            "[{}] TAU Request reports EBI(s) {inactive:?} inactive: deactivated locally (TS \
             24.301 §5.5.3.2.4); the Serving GW is told",
            mme_ue.imsi_bcd
        );
        // Off the UE pool lock: the release reads the UE back.
        drop(pool);
        crate::handover_switch::release_lost_bearers(ctx, mme_ue_id, &inactive);
    }
}

/// The EPS bearer contexts of `mme_ue` that a TRACKING AREA UPDATE REQUEST's EPS
/// bearer context status (`status`, bit n for EBI n) reports inactive (#993, TS
/// 24.301 §5.5.3.2.4). Returns (the EBIs to deactivate, every EBI that goes with
/// them, including the dedicated bearers of a PDN connection whose default
/// bearer goes).
///
/// The default bearer of the last remaining PDN connection is kept: this MME
/// does not support EMM-REGISTERED without PDN connection, and §5.5.3.2.4 then
/// deactivates a default bearer only when its PDN connection is not the last.
/// The first PDN connection of the UE is the one kept when the UE reports every
/// default bearer inactive.
fn reported_inactive(
    ctx: &MmeContext,
    mme_ue: &crate::context::MmeUe,
    status: u16,
) -> (Vec<u8>, Vec<u8>) {
    let active = |ebi: u8| ebi < 16 && status & (1 << ebi) != 0;
    // (PDN connection's bearers, its default EBI) in the UE's order.
    let pdns: Vec<(Vec<u8>, u8)> = mme_ue
        .sess_list
        .iter()
        .filter_map(|sess_id| {
            let sess = ctx.sess_find_by_id(*sess_id)?;
            let ebis: Vec<u8> = sess
                .bearer_list
                .iter()
                .filter_map(|id| ctx.bearer_find_by_id(*id))
                .map(|b| b.ebi)
                .collect();
            let default = *ebis.iter().min()?;
            Some((ebis, default))
        })
        .collect();
    // Every default bearer reported inactive: the first PDN connection stays.
    let keep_first = pdns.iter().all(|(_, default)| !active(*default));
    let mut inactive = Vec::new();
    let mut released = Vec::new();
    for (i, (ebis, default)) in pdns.iter().enumerate() {
        let kept = active(*default) || (keep_first && i == 0);
        if !kept {
            inactive.push(*default);
            released.extend_from_slice(ebis);
            continue;
        }
        for ebi in ebis.iter().filter(|e| **e != *default && !active(**e)) {
            inactive.push(*ebi);
            released.push(*ebi);
        }
    }
    (inactive, released)
}

/// Finish an inter-system TAU once the old AMF's context has been installed (#347).
///
/// TS 23.502 §4.11.1.3.2 steps 7-14 and 16-18, i.e. TS 23.401 §5.3.3.1 steps 6-12 and
/// 17-21: the transferred bearers are switched over to this MME's Serving GW with a
/// **Modify Bearer Request**, and the UE gets its **TAU ACCEPT**.
///
/// # Called from the N26 response path, which is reached from a live socket
///
/// [`crate::n26_path::handle_context_response`], reached from `N26Server::handle_datagram`,
/// which the receive thread `N26Server::open` spawns drives — installed by `main.rs` at
/// startup when the switch is on. Stated here because "correct but unreachable" is this
/// tree's commonest defect and a reader should not have to trace it.
///
/// # Why the accept is sent even if the Modify Bearer send fails
///
/// The UE's context, security and bearers are already installed here; the Modify Bearer
/// Request moves the *user plane*. TS 23.401 §5.3.3.1 sends the TAU ACCEPT at step 20,
/// after the bearer modification, but a UE left with no answer at all waits out T3430 and
/// then re-attaches — losing the context that was just transferred at some cost. So a
/// failed S11 send is logged loudly, naming the consequence (a UE registered on EPS whose
/// downlink path still points at the old SGW), and the accept goes out.
pub fn continue_inter_system_tau(ctx: &MmeContext, mme_ue_id: u64, enb_ue_id: u64) {
    let Some(enb_ue) = ctx.enb_ue_find_by_id(enb_ue_id) else {
        log::warn!(
            "the eNB UE context for the inter-system TAU is gone; the transferred context \
             is installed but no TAU ACCEPT can be sent"
        );
        return;
    };

    // TS 24.301 §5.5.3.2.4: the accept may reallocate the GUTI, and rotating it on
    // mobility is what keeps the temporary identity temporary (#46). It matters more here
    // than on an intra-EPS TAU: the UE arrived holding a GUTI *mapped from its 5G-GUTI*,
    // so leaving it in place would keep an EPS identity that encodes which AMF served it.
    ctx.allocate_guti(mme_ue_id);

    // Steps 8-11: switch the transferred bearers to this MME's Serving GW. `uli_presence`
    // is true because the UE has changed tracking area by definition -- that is what a TAU
    // is -- so the SGW and PGW need the new User Location Information.
    match gtp_path::send_modify_bearer_request(
        ctx,
        enb_ue_id,
        mme_ue_id,
        true,
        crate::s11_build::GtpModifyAction::NoAction,
    ) {
        Ok(_) => log::info!(
            "Inter-system TAU: Modify Bearer Request sent for the transferred bearers \
             (TS 23.401 §5.3.3.1 steps 8-11)"
        ),
        Err(e) => log::error!(
            "Inter-system TAU: Modify Bearer Request failed: {e}. The UE will be accepted \
             on EPS with its control-plane context transferred, but its DOWNLINK user plane \
             still points at the 5GC's UPF -- so downlink traffic is blackholed until a \
             later bearer procedure repairs it."
        ),
    }

    let bearers: Vec<crate::context::MmeBearer> = {
        let Some(mme_ue) = ctx.mme_ue_find_by_id(mme_ue_id) else {
            return;
        };
        mme_ue
            .sess_list
            .iter()
            .filter_map(|sess_id| ctx.sess_find_by_id(*sess_id))
            .flat_map(|sess| {
                sess.bearer_list
                    .iter()
                    .filter_map(|id| ctx.bearer_find_by_id(*id))
                    .collect::<Vec<_>>()
            })
            .collect()
    };

    let mut pool = ctx.mme_ue_pool.write().unwrap();
    let Some(mme_ue) = pool.get_mut(&mme_ue_id) else {
        return;
    };
    if let Err(e) = nas_path::nas_eps_send_tau_accept(
        mme_ue,
        &enb_ue,
        false,
        &bearers,
        s1ap_build::ue_ambr_of(ctx, mme_ue),
    ) {
        log::error!("[{}] TAU Accept send failed: {e}", mme_ue.imsi_bcd);
    } else {
        log::info!(
            "[{}] Inter-system TAU COMPLETE: the UE moved from 5GS to EPS with {} \
             transferred bearer(s) and its mapped EPS security context (TS 23.502 \
             §4.11.1.3.2)",
            mme_ue.imsi_bcd,
            bearers.len()
        );
    }
}

/// #702: a SERVICE REJECT ends the service request procedure, so the MME releases
/// the S1 connection it rode on: UE Context Release Command, cause NAS
/// normal-release (TS 23.401 §5.3.4.1, TS 36.413 §8.3.3).
///
/// Both causes sent here (#9, #40) make the UE re-attach once its NAS signalling
/// connection is released (TS 24.301 §5.6.1.5). Without this release the UE
/// waited for its local T3440 (10 s), and the eNB kept an S1 UE connection that
/// nothing would use again. The UE context goes too: after #9 it is a context for
/// an identity the network cannot derive, and after #40 the UE re-attaches.
/// Only the `enb_ue_pool` is locked, so this is safe under an `mme_ue_pool` guard.
fn release_after_service_reject(ctx: &MmeContext, enb_ue: &EnbUe) {
    release_ue_context_with_cause(ctx, enb_ue, s1ap_build::nas_cause::NORMAL_RELEASE);
}

fn emm_service_request(ctx: &MmeContext, enb_ue: &EnbUe, mme_ue_id: u64, pdu: &[u8]) {
    // TS 24.301 §8.2.25: SERVICE REQUEST is 4 octets — header, KSI and sequence
    // number, then a 2-octet short MAC.
    if pdu.len() < 4 {
        log::warn!(
            "SERVICE REQUEST from enb_ue_s1ap_id={} truncated ({} bytes)",
            enb_ue.enb_ue_s1ap_id,
            pdu.len()
        );
        return;
    }

    let has_bearers = ctx.mme_ue_have_active_eps_bearers(mme_ue_id);

    let mut pool = ctx.mme_ue_pool.write().unwrap();
    let Some(mme_ue) = pool.get_mut(&mme_ue_id) else {
        return;
    };
    mme_ue.nas_eps.type_ = MmeEpsType::ServiceRequest;

    // The short MAC is verified against the UE's NAS integrity key, so a UE the
    // MME has no security context for cannot be admitted.
    let mut message = pdu.to_vec();
    let flags = SecurityHeaderTypeFlags::from_header_type(SERVICE_REQUEST_HEADER_TYPE);
    if let Err(e) = nas_security::nas_eps_security_decode(mme_ue, flags, &mut message) {
        // TS 24.301 §5.6.1.5: with no context to verify against, the MME
        // rejects with EMM cause #9 so the UE re-attaches.
        log::info!(
            "SERVICE REQUEST on enb_ue_s1ap_id={} cannot be verified ({e}); rejecting",
            enb_ue.enb_ue_s1ap_id
        );
        if let Err(e) = nas_path::nas_eps_send_service_reject(
            enb_ue,
            mme_ue,
            EmmCause::UeIdentityCannotBeDerived,
        ) {
            log::error!("Service Reject send failed: {e}");
        }
        drop(pool);
        crate::paging::service_rejected(ctx, mme_ue_id);
        release_after_service_reject(ctx, enb_ue);
        return;
    }
    if std::mem::take(&mut mme_ue.mac_failed) {
        log::warn!(
            "[{}] SERVICE REQUEST integrity check failed; message discarded",
            mme_ue.imsi_bcd
        );
        return;
    }

    if let Err(e) = emm_handler::handle_service_request(enb_ue, mme_ue, &message[1..]) {
        log::warn!("[{}] SERVICE REQUEST rejected: {e}", mme_ue.imsi_bcd);
        return;
    }

    if !has_bearers {
        // TS 24.301 §5.6.1.5: EMM cause #40 when no EPS bearer context is
        // active. Bearers are created over S11, which is not implemented (#51).
        log::info!(
            "[{}] SERVICE REQUEST with no active EPS bearer; rejecting",
            mme_ue.imsi_bcd
        );
        if let Err(e) = nas_path::nas_eps_send_service_reject(
            enb_ue,
            mme_ue,
            EmmCause::NoEpsBearerContextActivated,
        ) {
            log::error!("Service Reject send failed: {e}");
        }
        drop(pool);
        crate::paging::service_rejected(ctx, mme_ue_id);
        release_after_service_reject(ctx, enb_ue);
        return;
    }

    drop(pool);
    service_request_initial_context_setup(ctx, enb_ue, mme_ue_id);
}

/// SERVICE REQUEST accepted (TS 23.401 §5.3.4.1 step 4, #956): the radio and
/// S1 bearers of every active EPS bearer are set up again with an INITIAL
/// CONTEXT SETUP REQUEST, with no NAS-PDU (a SERVICE REQUEST has no NAS
/// answer; the AS security mode is its acceptance, TS 24.301 §5.6.1.4).
///
/// K_eNB is derived afresh from K_ASME and the uplink NAS COUNT of the SERVICE
/// REQUEST (TS 33.401 §7.2.8.1, Annex A.3), and the NH chain restarts from it.
/// A paging the UE answered stops (TS 24.301 §5.6.2.2.1).
fn service_request_initial_context_setup(ctx: &MmeContext, enb_ue: &EnbUe, mme_ue_id: u64) {
    let was_paged = crate::paging::answered(ctx, mme_ue_id) != crate::context::PagingType::None;
    // The bearers established at the Serving GW (an S1-U SGW TEID): the ones a
    // never-connected subscription session lacks.
    let bearers: Vec<crate::context::MmeBearer> = crate::gtp_path::bearers_of_ue(ctx, mme_ue_id)
        .into_iter()
        .filter(|b| b.sgw_s1u_teid != 0)
        .collect();
    let mut pool = ctx.mme_ue_pool.write().unwrap();
    let Some(mme_ue) = pool.get_mut(&mme_ue_id) else {
        return;
    };
    mme_ue.kenb = nextgcore_crypt::kdf::nextgcore_kdf_kenb(&mme_ue.kasme, mme_ue.ul_count);
    mme_ue.nhcc = 0;
    mme_ue.nh = [0; 32];
    let ue_ambr = crate::s1ap_build::ue_ambr_of(ctx, mme_ue);
    match crate::s1ap_build::build_initial_context_setup_request(
        mme_ue, enb_ue, &bearers, None, ue_ambr,
    ) {
        Ok(pdu) => {
            mme_ue.service_request_ics_pending = true;
            // #869: a UE-AMBR change waits behind this setup, which carries the
            // value computed here.
            mme_ue.ics_pending_on = enb_ue.id;
            if let Err(e) = nas_path::nas_eps_send_to_enb(mme_ue, enb_ue, pdu) {
                mme_ue.service_request_ics_pending = false;
                mme_ue.ics_pending_on = 0;
                log::error!(
                    "[{}] SERVICE REQUEST: Initial Context Setup not sent: {e}",
                    mme_ue.imsi_bcd
                );
                return;
            }
            log::info!(
                "[{}] SERVICE REQUEST accepted: Initial Context Setup Request for E-RABs {:?} \
                 (TS 23.401 §5.3.4.1 step 4){}",
                mme_ue.imsi_bcd,
                bearers.iter().map(|b| b.ebi).collect::<Vec<_>>(),
                if was_paged { "; paging stopped" } else { "" }
            );
        }
        Err(e) => log::error!(
            "[{}] SERVICE REQUEST: Initial Context Setup Request not built: {e:?}",
            mme_ue.imsi_bcd
        ),
    }
}

fn emm_extended_service_request(ctx: &MmeContext, enb_ue: &EnbUe, mme_ue_id: u64, body: &[u8]) {
    let mut pool = ctx.mme_ue_pool.write().unwrap();
    let Some(mme_ue) = pool.get_mut(&mme_ue_id) else {
        return;
    };
    mme_ue.nas_eps.type_ = MmeEpsType::ExtendedServiceRequest;

    let service_type = match emm_handler::handle_extended_service_request(enb_ue, mme_ue, body) {
        Ok(service_type) => service_type,
        Err(e) => {
            log::warn!(
                "EXTENDED SERVICE REQUEST from enb_ue_s1ap_id={} rejected: {e}",
                enb_ue.enb_ue_s1ap_id
            );
            return;
        }
    };

    // #956, TS 24.301 §5.6.1.1 / Table 9.9.3.27.1: service type "packet
    // services via S1" (8, and the unused 9-11 read as it) is a SERVICE REQUEST
    // in all but the message: the user plane is set up again. It was refused
    // as a CS fallback with no SGs association.
    if service_type >= 8 {
        drop(pool);
        if !ctx.mme_ue_have_active_eps_bearers(mme_ue_id) {
            let mut pool = ctx.mme_ue_pool.write().unwrap();
            if let Some(mme_ue) = pool.get_mut(&mme_ue_id) {
                if let Err(e) = nas_path::nas_eps_send_service_reject(
                    enb_ue,
                    mme_ue,
                    EmmCause::NoEpsBearerContextActivated,
                ) {
                    log::error!("Service Reject send failed: {e}");
                }
            }
            drop(pool);
            crate::paging::service_rejected(ctx, mme_ue_id);
            release_after_service_reject(ctx, enb_ue);
            return;
        }
        service_request_initial_context_setup(ctx, enb_ue, mme_ue_id);
        return;
    }

    if mme_ue.csmap_id == NEXTGCORE_INVALID_POOL_ID {
        // TS 24.301 §5.6.1.5: CSFB needs an SGs association with a VLR.
        log::info!(
            "[{}] EXTENDED SERVICE REQUEST (service_type={service_type}) with no SGs \
             association; rejecting",
            mme_ue.imsi_bcd
        );
        if let Err(e) =
            nas_path::nas_eps_send_service_reject(enb_ue, mme_ue, EmmCause::CsDomainNotAvailable)
        {
            log::error!("Service Reject send failed: {e}");
        }
        return;
    }

    // TS 23.272 §7.2/§7.3: the MME triggers the fallback by sending the eNB a
    // UE CONTEXT MODIFICATION REQUEST carrying the CS Fallback Indicator. Until
    // #49 the codec had no such message, so an accepted Extended Service Request
    // went no further and no CS call — mobile-originated or terminated — could
    // ever fall back.
    match csfb_context_modification(enb_ue, service_type) {
        None => log::info!(
            "[{}] EXTENDED SERVICE REQUEST (service_type={service_type}) is a packet-services \
             request, not CS fallback",
            mme_ue.imsi_bcd
        ),
        Some(Ok(pdu)) => {
            log::info!(
                "[{}] EXTENDED SERVICE REQUEST (service_type={service_type}) accepted; sending \
                 UE Context Modification with the CS Fallback Indicator",
                mme_ue.imsi_bcd
            );
            s1ap_path::s1ap_send_pdu(enb_ue.enb_id, pdu);
        }
        Some(Err(e)) => log::error!(
            "[{}] failed to build the CSFB UE Context Modification: {e}",
            mme_ue.imsi_bcd
        ),
    }
}

/// The UE Context Modification a CS-fallback Extended Service Request calls for,
/// or `None` when the request is not a CS fallback at all.
///
/// Composed as one function so the whole decision — service type in, encoded
/// S1AP PDU out — is testable without a transport.
fn csfb_context_modification(
    enb_ue: &EnbUe,
    service_type: u8,
) -> Option<nextgcore_s1ap::S1apResult<Vec<u8>>> {
    let csfb = csfb_indicator_for(service_type)?;
    Some(s1ap_build::build_ue_context_modification_for_csfb(
        enb_ue,
        csfb == CsfbPriority::High,
    ))
}

/// Which CS Fallback Indicator an Extended Service Request's service type calls
/// for, or `None` when the request is not a CS fallback at all.
///
/// TS 24.301 §9.9.3.27: 0 is MO CSFB, 1 is MT CSFB, 2 is an MO CSFB **emergency
/// call**, and 3-4 are unused values the network must read as MO CSFB. 8 and
/// above are "packet services via S1", which is a different procedure and must
/// not put an eNB into CS fallback. The emergency case maps to
/// `cs-fallback-high-priority` so the eNB prioritises the redirection.
fn csfb_indicator_for(service_type: u8) -> Option<CsfbPriority> {
    match service_type {
        0 | 1 | 3 | 4 => Some(CsfbPriority::Normal),
        2 => Some(CsfbPriority::High),
        _ => None,
    }
}

/// The two CS Fallback Indicator values, named by what they mean here rather
/// than by their ASN.1 spelling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CsfbPriority {
    /// `cs-fallback-required`
    Normal,
    /// `cs-fallback-high-priority` (emergency call)
    High,
}

fn emm_detach_request(ctx: &MmeContext, enb_ue: &EnbUe, mme_ue_id: u64, body: &[u8]) {
    let switch_off = {
        let mut pool = ctx.mme_ue_pool.write().unwrap();
        let Some(mme_ue) = pool.get_mut(&mme_ue_id) else {
            return;
        };
        mme_ue.nas_eps.type_ = MmeEpsType::DetachRequestFromUe;

        let (detach_type, switch_off) =
            match emm_handler::handle_detach_request(enb_ue, mme_ue, body) {
                Ok(parsed) => parsed,
                Err(e) => {
                    log::warn!(
                        "Detach Request from enb_ue_s1ap_id={} rejected: {e}",
                        enb_ue.enb_ue_s1ap_id
                    );
                    return;
                }
            };

        log::info!(
            "[{}] Detach Request (type={detach_type}, switch_off={switch_off})",
            mme_ue.imsi_bcd
        );

        switch_off
    };

    // A retransmission (T3421, TS 24.301 §5.5.2.2.4) while the first Detach
    // Request's Delete Session Requests are unanswered is the same detach: it
    // keeps waiting rather than completing ahead of the Serving GW.
    if crate::gtp_path::detach_deletes_outstanding(mme_ue_id) {
        log::info!(
            "UE {mme_ue_id}: Detach Request retransmitted while its Delete Session Requests are \
             unanswered; still waiting"
        );
        return;
    }

    // TS 23.401 §5.3.8.2.1 step 2 (#1103): the gateways' sessions go first, by
    // a Delete Session Request (Operation Indication set, so the Serving GW
    // relays it to the PDN GW, step 3) per PDN connection. Before #1103 none
    // was sent and every detach leaked its sessions at the SGW and the PGW.
    // The PDN connections are released locally at once: the responses (or
    // their N3 exhaustion, so an unresponsive Serving GW cannot hold the detach
    // up) only complete the detach (steps 7-8, `on_detach_delete_answered`).
    let pending = crate::gtp_path::PendingDetach {
        mme_ue_id,
        enb_ue_id: enb_ue.id,
        switch_off,
    };
    let in_flight = crate::gtp_path::send_delete_all_sessions_for_detach(ctx, pending);
    crate::network_detach::delete_pdn_connections_locally(ctx, mme_ue_id);
    if in_flight == 0 {
        complete_ue_detach(ctx, pending);
    } else {
        log::info!(
            "UE {mme_ue_id}: {in_flight} Delete Session Request(s) sent; the detach completes \
             on their responses"
        );
    }
}

/// A Delete Session Request of a UE-initiated detach was answered, or its
/// retransmissions ran out (#1103): with none left outstanding the detach
/// completes.
pub(crate) fn on_detach_delete_answered(ctx: &MmeContext, pending: crate::gtp_path::PendingDetach) {
    if crate::gtp_path::detach_deletes_outstanding(pending.mme_ue_id) {
        return;
    }
    let still_detaching = ctx
        .mme_ue_find_by_id(pending.mme_ue_id)
        .is_some_and(|ue| ue.nas_eps.type_ == MmeEpsType::DetachRequestFromUe);
    if !still_detaching {
        // The context is gone (a retransmitted Detach Request completed the
        // detach, or a re-attach replaced it) or another procedure took it
        // over: there is nothing left to complete.
        log::info!(
            "UE {}: Delete Session Responses in, but the detach is no longer the procedure",
            pending.mme_ue_id
        );
        return;
    }
    complete_ue_detach(ctx, pending);
}

/// TS 23.401 §5.3.8.2.1 steps 7-8: DETACH ACCEPT (none for a switch-off, TS
/// 24.301 §5.5.2.2.2: the UE is no longer listening), then the UE context and
/// the S1 connection go.
fn complete_ue_detach(ctx: &MmeContext, pending: crate::gtp_path::PendingDetach) {
    // Only the S1 connection the detach came on, and only while it still
    // belongs to this UE.
    let enb_ue = ctx
        .enb_ue_find_by_id(pending.enb_ue_id)
        .filter(|e| e.mme_ue_id == pending.mme_ue_id);
    if let Some(enb_ue) = &enb_ue {
        if !pending.switch_off {
            let mut pool = ctx.mme_ue_pool.write().unwrap();
            if let Some(mme_ue) = pool.get_mut(&pending.mme_ue_id) {
                if let Err(e) = nas_path::nas_eps_send_detach_accept(mme_ue, enb_ue) {
                    log::error!("[{}] Detach Accept send failed: {e}", mme_ue.imsi_bcd);
                }
            }
        }
    }
    // Also drops whatever Delete Session records of this detach remain.
    ctx.mme_ue_remove(pending.mme_ue_id);
    if let Some(enb_ue) = enb_ue {
        release_ue_context(ctx, &enb_ue);
    }
}

/// Send an authentication challenge, or say why it cannot be sent.
fn authenticate(ctx: &MmeContext, enb_ue: &EnbUe, mme_ue_id: u64) {
    let mut pool = ctx.mme_ue_pool.write().unwrap();
    let Some(mme_ue) = pool.get_mut(&mme_ue_id) else {
        return;
    };

    if mme_ue.xres_len == 0 {
        // Vectors reach the context only through `s6a_handler::mme_s6a_handle_aia`,
        // so one has to be fetched from the HSS. `mme_s6a_send_air` is async and
        // this dispatch is not, so the request is queued for the main loop to run
        // (the same crossing `s1ap_path`'s send queue makes for downlink PDUs).
        // The AIR carries `resync_auts` when a synch failure stored one.
        log::info!(
            "[{}] Requesting authentication vectors from the HSS",
            mme_ue.imsi_bcd
        );
        crate::fd_path::queue_authentication_information(mme_ue_id);
        return;
    }

    if let Err(e) = nas_path::nas_eps_send_authentication_request(mme_ue, enb_ue) {
        log::error!(
            "[{}] Authentication Request send failed: {e}",
            mme_ue.imsi_bcd
        );
    }
}

/// Send IDENTITY REQUEST (IMSI), arming T3470's retransmission buffer.
fn request_identity(ctx: &MmeContext, enb_ue: &EnbUe, mme_ue_id: u64) {
    let mut pool = ctx.mme_ue_pool.write().unwrap();
    let Some(mme_ue) = pool.get_mut(&mme_ue_id) else {
        return;
    };
    if let Err(e) = nas_path::nas_eps_send_identity_request(mme_ue, enb_ue) {
        log::error!("Identity Request send failed: {e}");
    }
}

/// Index a UE context by IMSI, implicitly detaching any older context holding
/// the same identity.
///
/// Ordering matters: `mme_ue_remove` deletes the IMSI index entry belonging to
/// the *removed* context, so indexing the survivor first would drop the fresh
/// mapping on the floor.
fn index_imsi(ctx: &MmeContext, mme_ue_id: u64, imsi_bcd: &str) {
    if let Some(stale_id) = ctx
        .mme_ue_find_by_imsi(imsi_bcd)
        .filter(|id| *id != mme_ue_id)
    {
        // TS 24.301 §5.5.1.2.4: an Attach Request from a UE the MME already
        // holds context for implies an implicit detach of the old context.
        log::info!("[{imsi_bcd}] Re-attach: implicitly detaching stale UE context {stale_id}");
        let stale_enb_ue = ctx
            .mme_ue_find_by_id(stale_id)
            .map(|ue| ue.enb_ue_id)
            .filter(|id| *id != NEXTGCORE_INVALID_POOL_ID);
        // TS 23.401 §5.3.2.1 step 4 (#1103): "the new MME deletes these bearer
        // contexts by sending Delete Session Request messages to the GWs
        // involved". Before #1103 the old context was only forgotten, so every
        // re-attach leaked a PDN connection at the SGW and the PGW. The new
        // attach proceeds; only its Create Session Request waits for them
        // (`gtp_path::defer_create_while_replaced`).
        if let Err(e) =
            crate::gtp_path::send_delete_all_sessions_for_replaced(ctx, stale_id, imsi_bcd)
        {
            log::warn!("[{imsi_bcd}] Re-attach: Delete Session Requests not all sent: {e}");
        }
        crate::network_detach::delete_pdn_connections_locally(ctx, stale_id);
        ctx.mme_ue_remove(stale_id);
        if let Some(stale_enb_ue) = stale_enb_ue.and_then(|id| ctx.enb_ue_find_by_id(id)) {
            release_ue_context(ctx, &stale_enb_ue);
        }
    }

    ctx.mme_ue_set_imsi(mme_ue_id, imsi_bcd);
}

/// Ask the eNB to release a UE-associated logical S1 connection.
///
/// Crate-visible because `nas_timer` releases the connection when a NAS
/// procedure exhausts its retransmissions (TS 24.301 §5.4.2.7).
///
/// The eNB answers `UE CONTEXT RELEASE COMPLETE`, which
/// `s1ap_handler::handle_ue_context_release_complete` turns into the local
/// teardown — so the contexts are not dropped here.
pub(crate) fn release_ue_context(ctx: &MmeContext, enb_ue: &EnbUe) {
    release_ue_context_with_cause(ctx, enb_ue, nas_cause::DETACH);
}

/// [`release_ue_context`] with an explicit S1AP NAS cause (TS 36.413 §9.2.1.3).
///
/// Takes only the `enb_ue_pool` lock, briefly, so it is safe to call while the
/// caller holds an `mme_ue_pool` guard: no path holds `enb_ue_pool` while
/// waiting on `mme_ue_pool`.
pub(crate) fn release_ue_context_with_cause(ctx: &MmeContext, enb_ue: &EnbUe, cause: i64) {
    if let Some(stored) = ctx.enb_ue_pool.write().unwrap().get_mut(&enb_ue.id) {
        stored.ue_ctx_rel_action = UeCtxRelAction::UeContextRemove;
        stored.relcause.group = S1apCauseGroup::Nas;
        stored.relcause.cause = cause;
    }

    match s1ap_build::build_ue_context_release_command(
        Some(enb_ue.enb_ue_s1ap_id),
        enb_ue.mme_ue_s1ap_id,
        S1apCauseGroup::Nas,
        cause,
    ) {
        Ok(pdu) => {
            s1ap_path::s1ap_send_pdu(enb_ue.enb_id, pdu);
        }
        Err(e) => log::error!("Failed to build UE Context Release Command: {e}"),
    }
}

/// Hand an ESM container to the ESM entity through the documented NAS seam.
fn forward_to_esm(ctx: &MmeContext, enb_ue: &EnbUe, mme_ue_id: u64, esm_message: &[u8]) {
    // A clone, deliberately: `nas_eps_send_emm_to_esm` reaches back into
    // `MmeContext`, so it must not run under the `mme_ue_pool` guard.
    let Some(mme_ue) = ctx.mme_ue_find_by_id(mme_ue_id) else {
        return;
    };
    if let Err(e) = nas_path::nas_eps_send_emm_to_esm(ctx, enb_ue, &mme_ue, esm_message) {
        log::warn!("[{}] EMM-to-ESM forwarding failed: {e}", mme_ue.imsi_bcd);
    }
}

// ============================================================================
// ESM dispatch
// ============================================================================

/// Dispatch an ESM message (standalone, or the container carried by an EMM
/// message) into `esm_handler`.
///
/// `mme_ue` is a snapshot: the ESM handlers take it immutably, and calling this
/// with the `mme_ue_pool` guard held would deadlock on the session lookups.
pub fn handle_esm_message(ctx: &MmeContext, enb_ue: &EnbUe, mme_ue: &MmeUe, esm: &[u8]) {
    // TS 24.301 §9: EPS bearer identity + protocol discriminator, procedure
    // transaction identity, message type.
    if esm.len() < 3 {
        log::warn!(
            "[{}] ESM message too short ({} bytes)",
            mme_ue.imsi_bcd,
            esm.len()
        );
        return;
    }
    if esm[0] & 0x0f != NAS_PROTOCOL_DISCRIMINATOR_ESM {
        log::warn!(
            "[{}] ESM container has protocol discriminator 0x{:02x}; discarded",
            mme_ue.imsi_bcd,
            esm[0] & 0x0f
        );
        return;
    }

    let ebi = (esm[0] >> 4) & 0x0f;
    let pti = esm[1];
    let message_type = esm[2];
    let body = &esm[3..];

    // The ESM handlers all want a session and a bearer. A PDN CONNECTIVITY
    // REQUEST creates them (keyed by its procedure transaction identity);
    // anything else refers to what that request left behind.
    let (sess_id, bearer_id, created) = match message_type {
        esm_type::PDN_CONNECTIVITY_REQUEST => session_for_pti(ctx, mme_ue.id, pti),
        _ => match locate_session(ctx, mme_ue.id, pti, ebi) {
            Some((sess_id, bearer_id)) => (sess_id, bearer_id, false),
            None => {
                log::warn!(
                    "[{}] ESM 0x{message_type:02x} (pti={pti}, ebi={ebi}) has no session context",
                    mme_ue.imsi_bcd
                );
                return;
            }
        },
    };

    let (Some(sess), Some(bearer)) = (
        ctx.sess_find_by_id(sess_id),
        ctx.bearer_find_by_id(bearer_id),
    ) else {
        log::warn!("[{}] ESM session context vanished", mme_ue.imsi_bcd);
        return;
    };

    match message_type {
        esm_type::PDN_CONNECTIVITY_REQUEST => {
            // The create action follows the EMM procedure that carried the
            // container; a standalone request stands on its own.
            let create_action = match mme_ue.nas_eps.type_ {
                MmeEpsType::AttachRequest => CreateAction::InAttachRequest,
                MmeEpsType::TauRequest => CreateAction::InTauRequest,
                _ => CreateAction::InPdnConnectivityRequest,
            };

            match esm_handler::handle_pdn_connectivity_request(
                enb_ue,
                mme_ue,
                &sess,
                &bearer,
                body,
                create_action,
            ) {
                Ok(parsed) => {
                    log::info!(
                        "[{}] PDN Connectivity Request: apn[{}] pdn_type[{:?}] request_type[{}]",
                        mme_ue.imsi_bcd,
                        parsed.apn.as_deref().unwrap_or("<from ESM information>"),
                        parsed.pdn_type,
                        parsed.request_type
                    );
                    if let Some(sess) = ctx.sess_pool.write().unwrap().get_mut(&sess_id) {
                        sess.ue_request_type = parsed.request_type;
                        sess.ue_request_pdn_type = parsed.pdn_type;
                        if let Some(apn) = parsed.apn.clone() {
                            sess.apn = apn;
                        }
                        if let Some(pco) = parsed.pco.as_ref() {
                            sess.ue_pco.length = pco.len() as u16;
                            sess.ue_pco.buffer = pco.clone();
                        }
                        if let Some(epco) = parsed.epco.as_ref() {
                            sess.ue_epco.length = epco.len() as u16;
                            sess.ue_epco.buffer = epco.clone();
                        }
                    }

                    if parsed.esm_info_transfer_flag && parsed.apn.is_none() {
                        // TS 24.301 §6.5.1.2: the UE asked to send protocol
                        // configuration options / APN separately.
                        send_esm_information_request(ctx, enb_ue, mme_ue, bearer_id);
                        return;
                    }

                    // TS 23.401 §5.3.2.1: in an initial attach the Create Session
                    // Request is step 12, after the Update Location Answer (step 11)
                    // — it is built from the subscription the ULA returns (#479).
                    // Before, it was sent from here, ahead of the ULR, with no IMSI
                    // and no subscribed APN to pair with. The attach path now
                    // activates once both the request and the subscription exist.
                    if create_action == CreateAction::InAttachRequest {
                        activate_attach_pdn(ctx, mme_ue.id);
                        return;
                    }
                    // #329: send the Create Session Request for a standalone PDN
                    // connectivity request (or TAU), which already has the
                    // subscription.
                    send_s11_create_session(ctx, enb_ue.id, sess_id, create_action, mme_ue);
                }
                Err(e) => {
                    log::warn!(
                        "[{}] PDN Connectivity Request rejected: {e}",
                        mme_ue.imsi_bcd
                    );
                    let esm_cause = match e {
                        esm_handler::EsmError::NoSecurityContext => {
                            EsmCause::ProtocolErrorUnspecified
                        }
                        _ => EsmCause::InvalidMandatoryInformation,
                    };
                    let gtp_action = match create_action {
                        CreateAction::InAttachRequest => GtpCreateAction::InAttachRequest,
                        CreateAction::InTauRequest => GtpCreateAction::InTau,
                        CreateAction::InHandover => GtpCreateAction::InHandover,
                        CreateAction::InPdnConnectivityRequest => {
                            GtpCreateAction::InPdnConnectivity
                        }
                    };
                    if let Err(e) = nas_path::nas_eps_send_pdn_connectivity_reject(
                        ctx, &sess, mme_ue, enb_ue, esm_cause, gtp_action,
                    ) {
                        log::error!("PDN Connectivity Reject send failed: {e}");
                    }
                    // Do not leave the contexts this rejected request allocated
                    // behind: a UE that keeps sending unusable requests under
                    // fresh procedure transaction identities would otherwise
                    // grow the session and bearer pools without bound.
                    if created {
                        discard_session(ctx, mme_ue.id, sess_id, bearer_id);
                    }
                }
            }
        }
        esm_type::ESM_INFORMATION_RESPONSE => {
            match esm_handler::handle_esm_information_response(enb_ue, mme_ue, &sess, body) {
                Ok(parsed) => {
                    log::info!(
                        "[{}] ESM Information Response: apn[{}]",
                        mme_ue.imsi_bcd,
                        parsed.apn.as_deref().unwrap_or("<none>")
                    );
                    if let Some(sess) = ctx.sess_pool.write().unwrap().get_mut(&sess_id) {
                        if let Some(apn) = parsed.apn {
                            sess.apn = apn;
                        }
                        if let Some(pco) = parsed.pco {
                            sess.ue_pco.length = pco.len() as u16;
                            sess.ue_pco.buffer = pco;
                        }
                        if let Some(epco) = parsed.epco {
                            sess.ue_epco.length = epco.len() as u16;
                            sess.ue_epco.buffer = epco;
                        }
                    }
                    if let Some(bearer) = ctx.bearer_pool.write().unwrap().get_mut(&bearer_id) {
                        bearer.t3489.pkbuf = None;
                    }
                    // #329: the deferred half of the PDN Connectivity Request. The UE
                    // withheld its APN and sent it here (TS 24.301 §6.5.1.2), so this
                    // is where that session finally has enough to ask the SGW.
                    //
                    // The create action is re-derived from the EMM procedure rather
                    // than carried from the PDN Connectivity Request: the ESM
                    // Information Response arrives on the same EMM procedure, and
                    // re-reading it keeps one rule for both sites instead of a stored
                    // copy that can go stale.
                    let create_action = match mme_ue.nas_eps.type_ {
                        MmeEpsType::AttachRequest => CreateAction::InAttachRequest,
                        MmeEpsType::TauRequest => CreateAction::InTauRequest,
                        _ => CreateAction::InPdnConnectivityRequest,
                    };
                    // As above: an attach's session is activated after the ULA.
                    if create_action == CreateAction::InAttachRequest {
                        activate_attach_pdn(ctx, mme_ue.id);
                        return;
                    }
                    send_s11_create_session(ctx, enb_ue.id, sess_id, create_action, mme_ue);
                }
                Err(e) => log::warn!(
                    "[{}] ESM Information Response rejected: {e}",
                    mme_ue.imsi_bcd
                ),
            }
        }
        esm_type::ACTIVATE_DEFAULT_BEARER_ACCEPT => {
            match esm_handler::handle_activate_default_bearer_context_accept(
                enb_ue, mme_ue, &sess, &bearer, body,
            ) {
                Ok(()) => log::info!(
                    "[{}] Default EPS bearer (ebi={}) activated by the UE",
                    mme_ue.imsi_bcd,
                    bearer.ebi
                ),
                Err(e) => log::warn!(
                    "[{}] Activate Default accept rejected: {e}",
                    mme_ue.imsi_bcd
                ),
            }
        }
        esm_type::ACTIVATE_DEFAULT_BEARER_REJECT => {
            match esm_handler::handle_activate_default_bearer_context_reject(
                enb_ue, mme_ue, &sess, &bearer, body,
            ) {
                Ok(cause) => log::warn!(
                    "[{}] Default EPS bearer rejected by the UE: {cause:?}",
                    mme_ue.imsi_bcd
                ),
                Err(e) => log::warn!(
                    "[{}] Activate Default reject malformed: {e}",
                    mme_ue.imsi_bcd
                ),
            }
        }
        esm_type::ACTIVATE_DEDICATED_BEARER_ACCEPT => {
            match esm_handler::handle_activate_dedicated_bearer_context_accept(
                enb_ue, mme_ue, &sess, &bearer, body,
            ) {
                Ok(()) => {
                    log::info!(
                        "[{}] Dedicated EPS bearer (ebi={}) activated by the UE",
                        mme_ue.imsi_bcd,
                        bearer.ebi
                    );
                    // #641, TS 23.401 §5.4.1 step 7.
                    crate::bearer_activation::on_accept(ctx, mme_ue.id, bearer.ebi);
                }
                Err(e) => log::warn!(
                    "[{}] Activate Dedicated accept rejected: {e}",
                    mme_ue.imsi_bcd
                ),
            }
        }
        esm_type::ACTIVATE_DEDICATED_BEARER_REJECT => {
            match esm_handler::handle_activate_dedicated_bearer_context_reject(
                enb_ue, mme_ue, &sess, &bearer, body,
            ) {
                Ok(cause) => {
                    log::warn!(
                        "[{}] Dedicated EPS bearer rejected by the UE: {cause:?}",
                        mme_ue.imsi_bcd
                    );
                    // #641, TS 24.301 §6.4.2.5.
                    crate::bearer_activation::on_reject(ctx, mme_ue.id, bearer.ebi);
                }
                Err(e) => log::warn!(
                    "[{}] Activate Dedicated reject malformed: {e}",
                    mme_ue.imsi_bcd
                ),
            }
        }
        esm_type::MODIFY_BEARER_ACCEPT => {
            match esm_handler::handle_modify_bearer_context_accept(
                enb_ue, mme_ue, &sess, &bearer, body,
            ) {
                Ok(()) => {
                    log::info!(
                        "[{}] EPS bearer (ebi={}) modification accepted by the UE",
                        mme_ue.imsi_bcd,
                        bearer.ebi
                    );
                    // #641, TS 23.401 §5.4.2.1 step 7.
                    crate::bearer_modification::on_accept(ctx, mme_ue.id, bearer.ebi);
                }
                Err(e) => log::warn!("[{}] Modify accept rejected: {e}", mme_ue.imsi_bcd),
            }
        }
        esm_type::MODIFY_BEARER_REJECT => {
            match esm_handler::handle_modify_bearer_context_reject(
                enb_ue, mme_ue, &sess, &bearer, body,
            ) {
                Ok(cause) => {
                    log::warn!(
                        "[{}] EPS bearer modification rejected by the UE: {cause:?}",
                        mme_ue.imsi_bcd
                    );
                    crate::bearer_modification::on_reject(ctx, mme_ue.id, bearer.ebi);
                }
                Err(e) => log::warn!("[{}] Modify reject malformed: {e}", mme_ue.imsi_bcd),
            }
        }
        esm_type::DEACTIVATE_BEARER_ACCEPT => {
            match esm_handler::handle_deactivate_bearer_context_accept(
                enb_ue, mme_ue, &sess, &bearer, body,
            ) {
                Ok(()) => {
                    log::info!(
                        "[{}] EPS bearer (ebi={}) deactivated by the UE",
                        mme_ue.imsi_bcd,
                        bearer.ebi
                    );
                    // #734, TS 23.401 §5.4.4.1 step 7: a PDN GW initiated
                    // deactivation completes; the Serving GW is answered when
                    // its last bearer is done.
                    crate::bearer_deactivation::on_accept(ctx, mme_ue.id, bearer.ebi);
                }
                Err(e) => log::warn!("[{}] Deactivate accept rejected: {e}", mme_ue.imsi_bcd),
            }
        }
        esm_type::PDN_DISCONNECT_REQUEST => {
            match esm_handler::handle_pdn_disconnect_request(enb_ue, mme_ue, &sess, body) {
                Ok(linked_ebi) => log::info!(
                    "[{}] PDN Disconnect Request (linked ebi={linked_ebi}); the S11 Delete \
                     Session Request to the SGW is not implemented (#51)",
                    mme_ue.imsi_bcd
                ),
                Err(e) => log::warn!("[{}] PDN Disconnect Request rejected: {e}", mme_ue.imsi_bcd),
            }
        }
        esm_type::BEARER_RESOURCE_ALLOCATION_REQUEST => {
            match esm_handler::handle_bearer_resource_allocation_request(
                enb_ue, mme_ue, &sess, &bearer, body,
            ) {
                Ok(parsed) => log::info!(
                    "[{}] Bearer Resource Allocation Request (linked ebi={}); the S11 Bearer \
                     Resource Command to the SGW is not implemented (#51)",
                    mme_ue.imsi_bcd,
                    parsed.linked_ebi
                ),
                Err(e) => log::warn!(
                    "[{}] Bearer Resource Allocation Request rejected: {e}",
                    mme_ue.imsi_bcd
                ),
            }
        }
        esm_type::BEARER_RESOURCE_MODIFICATION_REQUEST => {
            match esm_handler::handle_bearer_resource_modification_request(
                enb_ue, mme_ue, &sess, &bearer, body,
            ) {
                Ok(_) => log::info!(
                    "[{}] Bearer Resource Modification Request; the S11 Bearer Resource Command \
                     to the SGW is not implemented (#51)",
                    mme_ue.imsi_bcd
                ),
                Err(e) => log::warn!(
                    "[{}] Bearer Resource Modification Request rejected: {e}",
                    mme_ue.imsi_bcd
                ),
            }
        }
        esm_type::ESM_STATUS => match esm_handler::handle_esm_status(enb_ue, mme_ue, body) {
            Ok(cause) => log::warn!("[{}] ESM Status: {cause:?}", mme_ue.imsi_bcd),
            Err(e) => log::warn!("[{}] ESM Status malformed: {e}", mme_ue.imsi_bcd),
        },
        esm_type::NOTIFICATION => match esm_handler::handle_notification(enb_ue, mme_ue, body) {
            Ok(indicator) => {
                log::info!("[{}] ESM Notification ({indicator})", mme_ue.imsi_bcd);
            }
            Err(e) => log::warn!("[{}] ESM Notification malformed: {e}", mme_ue.imsi_bcd),
        },
        other => log::warn!(
            "[{}] Unhandled ESM message type 0x{other:02x}",
            mme_ue.imsi_bcd
        ),
    }
}

/// Session and bearer for a PDN CONNECTIVITY REQUEST, creating them on first
/// use of the procedure transaction identity.
///
/// The third element reports whether this call allocated them, so a rejected
/// request can hand them back.
fn session_for_pti(ctx: &MmeContext, mme_ue_id: u64, pti: u8) -> (u64, u64, bool) {
    if let Some(sess_id) = ctx.sess_find_by_pti(mme_ue_id, pti) {
        if let Some(bearer_id) = ctx
            .sess_find_by_id(sess_id)
            .and_then(|sess| sess.bearer_list.first().copied())
        {
            return (sess_id, bearer_id, false);
        }
    }

    let sess_id = ctx.sess_add(mme_ue_id, pti);
    let bearer_id = ctx.bearer_add(sess_id, mme_ue_id);
    // `sess_add`/`bearer_add` only allocate; the parent links are the caller's.
    if let Some(sess) = ctx.sess_pool.write().unwrap().get_mut(&sess_id) {
        sess.bearer_list.push(bearer_id);
    }
    if let Some(mme_ue) = ctx.mme_ue_pool.write().unwrap().get_mut(&mme_ue_id) {
        mme_ue.sess_list.push(sess_id);
    }
    (sess_id, bearer_id, true)
}

/// Release a session and bearer allocated for a request that was rejected,
/// including the parent links [`session_for_pti`] added.
fn discard_session(ctx: &MmeContext, mme_ue_id: u64, sess_id: u64, bearer_id: u64) {
    ctx.bearer_remove(bearer_id);
    ctx.sess_remove(sess_id);
    if let Some(mme_ue) = ctx.mme_ue_pool.write().unwrap().get_mut(&mme_ue_id) {
        mme_ue.sess_list.retain(|id| *id != sess_id);
    }
}

/// Session and bearer an existing ESM message refers to, by EPS bearer identity
/// when it carries one, else by procedure transaction identity.
fn locate_session(ctx: &MmeContext, mme_ue_id: u64, pti: u8, ebi: u8) -> Option<(u64, u64)> {
    if ebi != 0 {
        if let Some(bearer_id) = ctx.bearer_find_by_ebi(mme_ue_id, ebi) {
            let sess_id = ctx
                .bearer_find_by_id(bearer_id)
                .map(|bearer| bearer.sess_id)?;
            return Some((sess_id, bearer_id));
        }
    }

    let sess_id = ctx.sess_find_by_pti(mme_ue_id, pti).or_else(|| {
        ctx.mme_ue_find_by_id(mme_ue_id)
            .and_then(|mme_ue| mme_ue.sess_list.first().copied())
    })?;
    let bearer_id = ctx
        .sess_find_by_id(sess_id)
        .and_then(|sess| sess.bearer_list.first().copied())?;
    Some((sess_id, bearer_id))
}

/// Ask the Serving GW to create the session's bearers over S11 (#329,
/// TS 23.401 §5.3.2.1 step 4).
///
/// Called from the two points where the ESM procedure has everything the Create
/// Session Request needs: a PDN Connectivity Request that carried its APN, and the
/// ESM Information Response that supplied one withheld from it. Both used to log
/// "the S11 Create Session Request to the SGW is not implemented (#51)" — and #51 had
/// in fact shipped the sender, the sequencing and the transport, leaving only this
/// call.
///
/// # Why the create action is mapped rather than passed through
///
/// The tree has THREE parallel create-action enums: `esm_build::CreateAction` (what
/// the ESM handlers take), `nas_path::GtpCreateAction` (what the ESM builders take)
/// and `s11_build::GtpCreateAction` (what the S11 builder takes). They are not
/// interchangeable and none is a superset — `s11_build`'s has `UplinkNasTransport` and
/// `PathSwitchRequest`, the others have `InPdnConnectivityRequest` and `InHandover`.
/// Unifying them is a separate change with its own blast radius; mapping explicitly
/// here at least puts the correspondence in one readable place instead of leaving the
/// next reader to infer it.
///
/// A failure is logged and NOT propagated to the UE as a reject. TS 23.401 has the MME
/// wait for the SGW; the ESM procedure is still open and its T3485/T3489 timers govern
/// what happens when no answer arrives, so synthesising a reject here would race them.
/// Activate the attach's PDN connection: pair the UE's PDN CONNECTIVITY REQUEST
/// with the subscribed APNs and send the S11 Create Session Request for the
/// chosen one (TS 23.401 §5.3.2.1 steps 11–12, #479).
///
/// Called from both halves that have to be present — the ULA (subscription) and
/// the UE's request (and its ESM INFORMATION RESPONSE when the APN was withheld)
/// — in whichever order they arrive; it does nothing until both are there, and
/// nothing a second time once the session is activated.
pub(crate) fn activate_attach_pdn(ctx: &MmeContext, mme_ue_id: u64) {
    let Some(mme_ue) = ctx.mme_ue_find_by_id(mme_ue_id) else {
        return;
    };
    let sessions: Vec<crate::context::MmeSess> = mme_ue
        .sess_list
        .iter()
        .filter_map(|id| ctx.sess_find_by_id(*id))
        .collect();
    // Subscribed sessions carry `session` (materialised from the ULA); the UE's
    // request is the session with a PTI and no subscription behind it.
    if !sessions.iter().any(|sess| sess.session.is_some()) {
        return; // the ULA has not arrived yet
    }
    if sessions
        .iter()
        .any(|sess| sess.session.is_some() && sess.pti != 0)
    {
        return; // already activated: a subscribed session holds the UE's PTI
    }
    let Some(requested) = sessions
        .iter()
        .find(|sess| sess.pti != 0 && sess.session.is_none())
        .cloned()
    else {
        return; // the UE's PDN CONNECTIVITY REQUEST has not been processed yet
    };
    let requested_bearer = requested.bearer_list.first().copied();
    if let Some(bearer) = requested_bearer.and_then(|id| ctx.bearer_find_by_id(id)) {
        if bearer.t3489.pkbuf.is_some() {
            return; // still waiting for the ESM INFORMATION RESPONSE (APN/PCO)
        }
    }

    let enb_ue = ctx
        .enb_ue_find_by_id(mme_ue.enb_ue_id)
        .filter(|enb_ue| enb_ue.id != 0);

    match crate::s6a_handler::reconcile_requested_apn(ctx, mme_ue_id) {
        Ok(chosen_id) => {
            // The UE's request options travel with it onto the subscribed session,
            // which is what the Create Session Request and the ESM accept use.
            if let Some(sess) = ctx.sess_pool.write().unwrap().get_mut(&chosen_id) {
                sess.ue_request_type = requested.ue_request_type;
                sess.ue_pco = requested.ue_pco.clone();
                sess.ue_epco = requested.ue_epco.clone();
            }
            if chosen_id != requested.id {
                if let Some(bearer_id) = requested_bearer {
                    discard_session(ctx, mme_ue_id, requested.id, bearer_id);
                }
            }
            let Some(enb_ue) = enb_ue else {
                log::warn!(
                    "[{}] no S1 connection to activate the PDN connection on",
                    mme_ue.imsi_bcd
                );
                return;
            };
            send_s11_create_session(
                ctx,
                enb_ue.id,
                chosen_id,
                CreateAction::InAttachRequest,
                &mme_ue,
            );
        }
        Err(esm_cause) => {
            let mut pool = ctx.mme_ue_pool.write().unwrap();
            if let (Some(enb_ue), Some(mme_ue)) = (enb_ue, pool.get_mut(&mme_ue_id)) {
                log::warn!("[{}] rejecting the attach: {esm_cause:?}", mme_ue.imsi_bcd);
                // TS 24.301 §5.5.1.2.5: an ESM failure during attach is EMM cause
                // #19, with the ESM cause piggybacked so the UE learns which APN
                // was refused.
                if let Err(e) = nas_path::nas_eps_send_attach_reject(
                    ctx,
                    &enb_ue,
                    mme_ue,
                    EmmCause::EsmFailure,
                    Some(esm_cause),
                ) {
                    log::error!("Attach Reject send failed: {e}");
                }
            }
        }
    }
}

fn send_s11_create_session(
    ctx: &MmeContext,
    enb_ue_id: u64,
    sess_id: u64,
    create_action: CreateAction,
    mme_ue: &MmeUe,
) {
    let gtp_action = match create_action {
        CreateAction::InAttachRequest => S11CreateAction::AttachRequest,
        CreateAction::InTauRequest => S11CreateAction::TrackingAreaUpdate,
        // A standalone PDN Connectivity Request arrives in an Uplink NAS Transport,
        // which is exactly what TS 29.274's create action distinguishes it by.
        CreateAction::InPdnConnectivityRequest => S11CreateAction::UplinkNasTransport,
        CreateAction::InHandover => S11CreateAction::PathSwitchRequest,
    };

    // #1103: a request for this IMSI must not reach the Serving GW ahead of the
    // deletions of the context its re-attach replaced.
    if gtp_path::defer_create_while_replaced(
        &mme_ue.imsi_bcd,
        mme_ue.id,
        enb_ue_id,
        sess_id,
        gtp_action,
    ) {
        log::info!(
            "[{}] S11 Create Session Request held until the replaced context's Delete Session \
             Requests are answered",
            mme_ue.imsi_bcd
        );
        return;
    }
    match gtp_path::send_create_session_request(ctx, enb_ue_id, sess_id, gtp_action) {
        Ok(xact) => log::info!(
            "[{}] S11 Create Session Request sent to the SGW (action={gtp_action:?}, \
             local S11 TEID {:#x})",
            mme_ue.imsi_bcd,
            xact.local_teid
        ),
        Err(e) => log::error!(
            "[{}] S11 Create Session Request could not be sent: {e:?} — the ESM \
             procedure stays open and its timer governs the outcome",
            mme_ue.imsi_bcd
        ),
    }
}

/// Send ESM INFORMATION REQUEST, arming T3489's retransmission buffer.
fn send_esm_information_request(ctx: &MmeContext, enb_ue: &EnbUe, mme_ue: &MmeUe, bearer_id: u64) {
    log::info!(
        "[{}] Requesting ESM information (APN/PCO) from the UE",
        mme_ue.imsi_bcd
    );
    if let Err(e) = nas_path::nas_eps_send_esm_information_request(ctx, bearer_id, mme_ue, enb_ue) {
        log::error!(
            "[{}] ESM Information Request send failed: {e}",
            mme_ue.imsi_bcd
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
    use crate::esm_build::{EsmMessageType, PdnType};

    const TEST_IMSI: &str = "001010123456789";
    const TEST_APN: &str = "inet";

    /// TS 24.301 §9.9.3.27. The interesting cases are the two the network must
    /// *not* treat alike: an emergency CS fallback needs priority handling, and
    /// "packet services via S1" is not a CS fallback at all — putting an eNB
    /// into CS fallback for it would redirect a UE that only wanted PS bearers.
    #[test]
    fn test_csfb_indicator_follows_the_service_type() {
        assert_eq!(csfb_indicator_for(0), Some(CsfbPriority::Normal)); // MO CSFB
        assert_eq!(csfb_indicator_for(1), Some(CsfbPriority::Normal)); // MT CSFB
        assert_eq!(csfb_indicator_for(2), Some(CsfbPriority::High)); // MO emergency

        // 3 and 4 are unused values the network reads as MO CS fallback.
        assert_eq!(csfb_indicator_for(3), Some(CsfbPriority::Normal));
        assert_eq!(csfb_indicator_for(4), Some(CsfbPriority::Normal));

        // 8..=11 are "packet services via S1": a different procedure entirely.
        for service_type in 8..=11 {
            assert_eq!(
                csfb_indicator_for(service_type),
                None,
                "service type {service_type} is not CS fallback"
            );
        }
    }

    /// The MT CSFB trigger, end to end from the service type: an MT CS fallback
    /// Extended Service Request must produce a real S1AP UE CONTEXT MODIFICATION
    /// REQUEST carrying the CS Fallback Indicator and addressed to the UE's S1
    /// connection. Before #49 this path logged "out of scope" and sent nothing,
    /// so MT CSFB voice could not be triggered at all.
    #[test]
    fn test_mt_csfb_emits_a_ue_context_modification_with_the_csfb_indicator() {
        let enb_ue = EnbUe {
            id: 1,
            enb_id: 9,
            enb_ue_s1ap_id: 100,
            mme_ue_s1ap_id: 4242,
            ..Default::default()
        };

        // Service type 1: mobile terminating CS fallback.
        let pdu = csfb_context_modification(&enb_ue, 1)
            .expect("an MT CS fallback must produce a modification")
            .expect("it must encode");
        match crate::s1ap_gen::test_codec::decode_s1ap_pdu(&pdu).unwrap() {
            nextgcore_s1ap::S1apMessage::UeContextModificationRequest(req) => {
                assert_eq!(req.mme_ue_s1ap_id, 4242);
                assert_eq!(req.enb_ue_s1ap_id, 100);
                assert_eq!(
                    req.cs_fallback_indicator,
                    Some(nextgcore_s1ap::CsFallbackIndicator::CsFallbackRequired)
                );
            }
            other => panic!("expected UeContextModificationRequest, got {other:?}"),
        }

        // Service type 2: an emergency call gets priority handling.
        let pdu = csfb_context_modification(&enb_ue, 2).unwrap().unwrap();
        match crate::s1ap_gen::test_codec::decode_s1ap_pdu(&pdu).unwrap() {
            nextgcore_s1ap::S1apMessage::UeContextModificationRequest(req) => {
                assert_eq!(
                    req.cs_fallback_indicator,
                    Some(nextgcore_s1ap::CsFallbackIndicator::CsFallbackHighPriority)
                );
            }
            other => panic!("expected UeContextModificationRequest, got {other:?}"),
        }

        // Service type 8: packet services via S1, so no CS fallback is triggered.
        assert!(
            csfb_context_modification(&enb_ue, 8).is_none(),
            "a packet-services request must not put the eNB into CS fallback"
        );
    }

    /// TS 23.401 §5.3.2.1 step 23 (#495): the Modify Bearer Request goes out only
    /// once BOTH the ATTACH COMPLETE and the Initial Context Setup Response (the
    /// eNB's S1-U TEID) are in, whichever comes second, and only once.
    #[test]
    fn the_attach_modify_bearer_waits_for_both_attach_complete_and_ics_response() {
        let ctx = test_ctx();
        let enb_ue_id = enb_with_connection(&ctx);
        let mme_ue_id = ctx.mme_ue_add(enb_ue_id);
        let sess_id = ctx.sess_add(mme_ue_id, 1);
        let bearer_id = ctx.bearer_add(sess_id, mme_ue_id);
        if let Some(b) = ctx.bearer_pool.write().unwrap().get_mut(&bearer_id) {
            b.ebi = 5;
        }
        ctx.sess_pool
            .write()
            .unwrap()
            .get_mut(&sess_id)
            .unwrap()
            .bearer_list
            .push(bearer_id);
        ctx.mme_ue_pool
            .write()
            .unwrap()
            .get_mut(&mme_ue_id)
            .unwrap()
            .sess_list
            .push(sess_id);
        let sent = |ctx: &MmeContext| {
            ctx.mme_ue_find_by_id(mme_ue_id)
                .unwrap()
                .attach_modify_bearer_sent
        };

        // Neither in: nothing.
        modify_bearer_after_attach(&ctx, enb_ue_id, mme_ue_id);
        assert!(!sent(&ctx));

        // ICS response only (eNB TEID known, no ATTACH COMPLETE): still nothing.
        if let Some(b) = ctx.bearer_pool.write().unwrap().get_mut(&bearer_id) {
            b.enb_s1u_teid = 0x0a0b_0c0d;
        }
        modify_bearer_after_attach(&ctx, enb_ue_id, mme_ue_id);
        assert!(!sent(&ctx), "step 23 needs the ATTACH COMPLETE too");

        // Both in: sent (the S11 send itself fails here, no socket; the decision is
        // what is under test).
        ctx.mme_ue_pool
            .write()
            .unwrap()
            .get_mut(&mme_ue_id)
            .unwrap()
            .attach_completed = true;
        modify_bearer_after_attach(&ctx, enb_ue_id, mme_ue_id);
        assert!(
            sent(&ctx),
            "both arrived: the Modify Bearer Request must be sent"
        );
    }

    /// And with the ATTACH COMPLETE in but no eNB S1-U TEID yet, it waits for the
    /// Initial Context Setup Response, then fires from the response handler.
    #[test]
    fn the_ics_response_triggers_the_attach_modify_bearer_when_it_arrives_second() {
        let ctx = test_ctx();
        let enb_ue_id = enb_with_connection(&ctx);
        let mme_ue_id = ctx.mme_ue_add(enb_ue_id);
        let sess_id = ctx.sess_add(mme_ue_id, 1);
        let bearer_id = ctx.bearer_add(sess_id, mme_ue_id);
        if let Some(b) = ctx.bearer_pool.write().unwrap().get_mut(&bearer_id) {
            b.ebi = 5;
        }
        ctx.sess_pool
            .write()
            .unwrap()
            .get_mut(&sess_id)
            .unwrap()
            .bearer_list
            .push(bearer_id);
        ctx.mme_ue_pool
            .write()
            .unwrap()
            .get_mut(&mme_ue_id)
            .unwrap()
            .sess_list
            .push(sess_id);
        ctx.mme_ue_pool
            .write()
            .unwrap()
            .get_mut(&mme_ue_id)
            .unwrap()
            .attach_completed = true;
        modify_bearer_after_attach(&ctx, enb_ue_id, mme_ue_id);
        assert!(
            !ctx.mme_ue_find_by_id(mme_ue_id)
                .unwrap()
                .attach_modify_bearer_sent,
            "no eNB S1-U TEID yet"
        );

        // Linked as the attach path links them (an S1 connection serving this UE).
        ctx.enb_ue_pool
            .write()
            .unwrap()
            .get_mut(&enb_ue_id)
            .unwrap()
            .mme_ue_id = mme_ue_id;
        let enb_ue = ctx.enb_ue_find_by_id(enb_ue_id).unwrap();
        let enb_id = enb_ue.enb_id;
        crate::s1ap_handler::handle_initial_context_setup_response(
            &ctx,
            enb_id,
            &nextgcore_s1ap::InitialContextSetupResponse {
                mme_ue_s1ap_id: enb_ue.mme_ue_s1ap_id,
                enb_ue_s1ap_id: enb_ue.enb_ue_s1ap_id,
                erab_setup_list: vec![nextgcore_s1ap::ErabSetupItem {
                    erab_id: 5,
                    transport_layer_address: vec![10, 0, 0, 7],
                    gtp_teid: 0x1122_3344,
                }],
                erab_failed_list: vec![],
            },
        );
        assert!(
            ctx.mme_ue_find_by_id(mme_ue_id)
                .unwrap()
                .attach_modify_bearer_sent,
            "the ICS response arriving second must send the step-23 Modify Bearer Request"
        );
    }

    /// ATTACH COMPLETE arriving second (ICS response already in) records the
    /// completion AND sends the step-23 Modify Bearer Request (#495).
    #[test]
    fn attach_complete_arriving_second_sends_the_attach_modify_bearer() {
        let ctx = test_ctx();
        let enb_ue_id = enb_with_connection(&ctx);
        let mme_ue_id = ctx.mme_ue_add(enb_ue_id);
        let sess_id = ctx.sess_add(mme_ue_id, 1);
        let bearer_id = ctx.bearer_add(sess_id, mme_ue_id);
        if let Some(b) = ctx.bearer_pool.write().unwrap().get_mut(&bearer_id) {
            b.ebi = 5;
            b.enb_s1u_teid = 0x1122_3344; // the ICS response is already in
        }
        ctx.sess_pool
            .write()
            .unwrap()
            .get_mut(&sess_id)
            .unwrap()
            .bearer_list
            .push(bearer_id);
        ctx.mme_ue_pool
            .write()
            .unwrap()
            .get_mut(&mme_ue_id)
            .unwrap()
            .sess_list
            .push(sess_id);
        let enb_ue = ctx.enb_ue_find_by_id(enb_ue_id).unwrap();

        // ESM message container (TS 24.301 §8.2.2): length 3, then ACTIVATE DEFAULT
        // EPS BEARER CONTEXT ACCEPT for EBI 5 -- octet 1 0x52, PTI 0, type 0xc2.
        let body = [0x00, 0x03, 0x52, 0x00, 0xc2];
        emm_attach_complete(&ctx, &enb_ue, mme_ue_id, &body);

        let ue = ctx.mme_ue_find_by_id(mme_ue_id).unwrap();
        assert!(ue.attach_completed, "ATTACH COMPLETE must be recorded");
        assert!(
            ue.attach_modify_bearer_sent,
            "with the ICS response already in, ATTACH COMPLETE must send the step-23 \
             Modify Bearer Request"
        );
    }

    fn test_ctx() -> MmeContext {
        let ctx = MmeContext::new();
        ctx.init();
        ctx
    }

    /// eNB plus one S1 connection with no UE context yet, as an
    /// `INITIAL UE MESSAGE` would leave things.
    fn enb_with_connection(ctx: &MmeContext) -> u64 {
        let enb_id = ctx.enb_add("127.0.0.1:36412".parse().unwrap());
        ctx.enb_ue_add(enb_id, 100)
    }

    /// EPS mobile identity holding [`TEST_IMSI`] (TS 24.301 §9.9.3.12): digit 1
    /// in the high nibble of octet 1, odd count, identity type 001, then the
    /// remaining digits packed two per octet, low nibble first.
    fn imsi_identity() -> Vec<u8> {
        vec![0x09, 0x10, 0x10, 0x10, 0x32, 0x54, 0x76, 0x98]
    }

    /// GUTI mobile identity (identity type 110) for MCC/MNC 001/01.
    fn guti_identity(mme_gid: u16, mme_code: u8, m_tmsi: u32) -> Vec<u8> {
        let mut identity = vec![0xf6, 0x00, 0xf1, 0x10];
        identity.extend_from_slice(&mme_gid.to_be_bytes());
        identity.push(mme_code);
        identity.extend_from_slice(&m_tmsi.to_be_bytes());
        identity
    }

    /// PDN CONNECTIVITY REQUEST: EBI 0, the given PTI, request type 1
    /// (initial), PDN type 1 (IPv4).
    ///
    /// With `esm_info_transfer` the UE asks to send the APN separately; without
    /// it the APN travels in the request as the DNS-label form of `TEST_APN`.
    fn pdn_connectivity_request(pti: u8, esm_info_transfer: bool) -> Vec<u8> {
        let mut esm = vec![
            NAS_PROTOCOL_DISCRIMINATOR_ESM,
            pti,
            EsmMessageType::PdnConnectivityRequest as u8,
            0x11,
        ];
        if esm_info_transfer {
            esm.push(0xd1);
        } else {
            esm.extend_from_slice(&[0x28, 0x05, 0x04, b'i', b'n', b'e', b't']);
        }
        esm
    }

    /// Plain ATTACH REQUEST carrying `identity` and `esm_container`.
    fn attach_request(identity: &[u8], esm_container: &[u8]) -> Vec<u8> {
        let mut pdu = vec![
            NAS_PROTOCOL_DISCRIMINATOR_EMM,
            NasEpsMessageType::AttachRequest as u8,
            0x71, // EPS attach, KSI 7 (no key available)
            identity.len() as u8,
        ];
        pdu.extend_from_slice(identity);
        pdu.extend_from_slice(&[0x02, 0xf0, 0xf0]); // UE network capability
        pdu.extend_from_slice(&(esm_container.len() as u16).to_be_bytes());
        pdu.extend_from_slice(esm_container);
        pdu
    }

    fn uplink(enb_ue_id: u64, nas_pdu: &[u8]) -> UplinkNas<'_> {
        UplinkNas {
            enb_ue_id,
            nas_pdu,
            s_tmsi: None,
        }
    }

    fn emm_message_type(pkbuf: &Option<Vec<u8>>) -> Option<u8> {
        let buf = pkbuf.as_ref()?;
        (buf.first() == Some(&NAS_PROTOCOL_DISCRIMINATOR_EMM))
            .then(|| buf.get(1).copied())
            .flatten()
    }

    /// Message type of a message the MME sent under a security header
    /// (6 octets: header type / PD, 4-octet MAC, sequence number).
    fn protected_message_type(pkbuf: &Option<Vec<u8>>) -> Option<u8> {
        let buf = pkbuf.as_ref()?;
        (buf.len() > 7 && buf[0] & 0x0f == NAS_PROTOCOL_DISCRIMINATOR_EMM && buf[0] >> 4 != 0)
            .then(|| buf[7])
    }

    /// Wrap `plain` in an integrity-protected uplink security header carrying
    /// the MAC a UE holding the same NAS context would compute.
    ///
    /// The MME derives its verification count from the sequence number in the
    /// header, so with no overflow the count *is* that sequence number.
    fn protect_uplink(mme_ue: &MmeUe, sequence_number: u8, plain: &[u8]) -> Vec<u8> {
        let mut protected = vec![
            ((crate::emm_build::SecurityHeaderType::IntegrityProtected as u8) << 4)
                | NAS_PROTOCOL_DISCRIMINATOR_EMM,
            0,
            0,
            0,
            0, // MAC, filled in below
            sequence_number,
        ];
        protected.extend_from_slice(plain);

        let mac = nas_security::nas_mac_calculate(
            mme_ue.selected_int_algorithm,
            &mme_ue.knas_int,
            u32::from(sequence_number),
            nas_security::NAS_SECURITY_BEARER,
            nas_security::NAS_SECURITY_UPLINK_DIRECTION,
            &protected[5..],
        );
        protected[1..5].copy_from_slice(&mac);
        protected
    }

    /// A UE context with an HSS vector and the capabilities of a UE supporting
    /// EEA/EIA 0-3, as an Attach Request would have left it.
    fn ue_with_vector(ctx: &MmeContext, enb_ue_id: u64) -> u64 {
        let mme_ue_id = ctx.mme_ue_add(enb_ue_id);
        ctx.enb_ue_associate_mme_ue(enb_ue_id, mme_ue_id);
        ctx.mme_ue_set_imsi(mme_ue_id, TEST_IMSI);
        let mut pool = ctx.mme_ue_pool.write().unwrap();
        let mme_ue = pool.get_mut(&mme_ue_id).unwrap();
        mme_ue.xres[..8].copy_from_slice(&[0xaa; 8]);
        mme_ue.xres_len = 8;
        mme_ue.rand = [0x11; 16];
        mme_ue.autn = [0x22; 16];
        mme_ue.kasme = [0x44; 32];
        mme_ue.ue_network_capability.eea = 0xf0;
        mme_ue.ue_network_capability.eia = 0xf0;
        mme_ue_id
    }

    /// AUTHENTICATION RESPONSE echoing the XRES `ue_with_vector` seeded.
    fn authentication_response() -> Vec<u8> {
        let mut pdu = vec![
            NAS_PROTOCOL_DISCRIMINATOR_EMM,
            NasEpsMessageType::AuthenticationResponse as u8,
            0x08,
        ];
        pdu.extend_from_slice(&[0xaa; 8]);
        pdu
    }

    /// #734: the ESM DEACTIVATE EPS BEARER CONTEXT ACCEPT reaches the PDN GW
    /// initiated deactivation, which deletes the bearer and settles the request.
    #[test]
    fn a_deactivate_accept_settles_the_bearer_deactivation() {
        let _guard = crate::gtp_path::lock_s11();
        crate::bearer_deactivation::clear_for_test();
        let ctx = test_ctx();
        let enb_ue_id = enb_with_connection(&ctx);
        let mme_ue_id = ue_with_vector(&ctx, enb_ue_id);
        let sess_id = ctx.sess_add(mme_ue_id, 1);
        for ebi in [5u8, 6] {
            let id = ctx.bearer_add(sess_id, mme_ue_id);
            ctx.bearer_pool.write().unwrap().get_mut(&id).unwrap().ebi = ebi;
            ctx.sess_pool
                .write()
                .unwrap()
                .get_mut(&sess_id)
                .unwrap()
                .bearer_list
                .push(id);
        }
        ctx.mme_ue_pool
            .write()
            .unwrap()
            .get_mut(&mme_ue_id)
            .unwrap()
            .sess_list
            .push(sess_id);
        assert!(crate::bearer_deactivation::start(
            &ctx,
            mme_ue_id,
            "127.0.0.1:2123".parse().unwrap(),
            0x734,
            0x5ca1,
            crate::bearer_deactivation::DeleteBearerAnswer::Ebis(vec![6]),
            None,
            &[6],
            false,
        ));
        assert_eq!(crate::bearer_deactivation::pending_count(), 1);
        let enb_ue = ctx.enb_ue_find_by_id(enb_ue_id).unwrap();
        let mme_ue = ctx.mme_ue_find_by_id(mme_ue_id).unwrap();
        // DEACTIVATE EPS BEARER CONTEXT ACCEPT, EBI 6.
        handle_esm_message(&ctx, &enb_ue, &mme_ue, &[0x62, 0x00, 0xce]);
        assert_eq!(crate::bearer_deactivation::pending_count(), 0);
        assert!(ctx.bearer_find_by_ebi(mme_ue_id, 6).is_none());
        assert!(ctx.bearer_find_by_ebi(mme_ue_id, 5).is_some());
    }

    /// A UE in a network-initiated detach of `detach_type`, DETACH REQUEST sent
    /// and T3422 running, on a live S1 connection.
    fn ue_in_network_detach(
        ctx: &MmeContext,
        detach_type: crate::emm_build::DetachTypeToUe,
    ) -> (u64, u64) {
        let enb_ue_id = enb_with_connection(ctx);
        let mme_ue_id = ue_with_vector(ctx, enb_ue_id);
        assert_eq!(
            crate::network_detach::mme_initiated_detach(ctx, mme_ue_id, detach_type, "test"),
            crate::network_detach::DetachOutcome::DetachRequestSent
        );
        let ue = ctx.mme_ue_find_by_id(mme_ue_id).unwrap();
        assert!(ue.t3422.is_running());
        assert_eq!(ue.nas_eps.type_, MmeEpsType::DetachRequestToUe);
        (enb_ue_id, mme_ue_id)
    }

    /// #732, TS 24.301 §5.5.2.3.5 d: an ATTACH REQUEST during a "re-attach
    /// required" detach aborts the detach (T3422 stopped) and the attach is
    /// progressed. Before #732 T3422 kept running and its fifth expiry released
    /// the re-attaching UE.
    #[test]
    fn an_attach_aborts_a_reattach_required_detach() {
        let ctx = test_ctx();
        let (enb_ue_id, mme_ue_id) =
            ue_in_network_detach(&ctx, crate::emm_build::DetachTypeToUe::ReAttachRequired);

        let pdu = attach_request(&imsi_identity(), &pdn_connectivity_request(1, false));
        nas_eps_handle_uplink(&ctx, uplink(enb_ue_id, &pdu));

        let ue = ctx
            .mme_ue_find_by_id(mme_ue_id)
            .expect("the context is kept");
        assert!(!ue.t3422.is_running(), "T3422 stopped");
        assert!(
            ue.t3422.pkbuf.is_none(),
            "no stale DETACH REQUEST to resend"
        );
        assert_eq!(ue.network_detach_type, None);
        assert_eq!(
            ue.nas_eps.type_,
            MmeEpsType::AttachRequest,
            "the attach is progressed"
        );
    }

    /// #732, §5.5.2.3.5 d: during a "re-attach not required" detach (an HSS
    /// subscription withdrawal) the ATTACH REQUEST is ignored.
    #[test]
    fn an_attach_during_a_reattach_not_required_detach_is_ignored() {
        let ctx = test_ctx();
        let (enb_ue_id, mme_ue_id) =
            ue_in_network_detach(&ctx, crate::emm_build::DetachTypeToUe::ReAttachNotRequired);

        let pdu = attach_request(&imsi_identity(), &pdn_connectivity_request(1, false));
        nas_eps_handle_uplink(&ctx, uplink(enb_ue_id, &pdu));

        let ue = ctx.mme_ue_find_by_id(mme_ue_id).unwrap();
        assert!(ue.t3422.is_running(), "the detach is still supervised");
        assert_eq!(ue.nas_eps.type_, MmeEpsType::DetachRequestToUe);
    }

    /// #732, §5.5.2.3.5 e and f: a TAU REQUEST and a SERVICE REQUEST during the
    /// detach are ignored and the detach progresses: T3422 keeps running and a
    /// later DETACH ACCEPT still completes it.
    #[test]
    fn a_tau_or_service_request_during_a_detach_is_ignored() {
        let ctx = test_ctx();
        let (enb_ue_id, mme_ue_id) =
            ue_in_network_detach(&ctx, crate::emm_build::DetachTypeToUe::ReAttachRequired);

        // A plain TAU REQUEST (on the unprotected allowlist) and a SERVICE
        // REQUEST (security header type 12).
        let tau = [NAS_PROTOCOL_DISCRIMINATOR_EMM, emm_type::TAU_REQUEST, 0x70];
        nas_eps_handle_uplink(&ctx, uplink(enb_ue_id, &tau));
        let ue = ctx.mme_ue_find_by_id(mme_ue_id).unwrap();
        assert_eq!(
            ue.nas_eps.type_,
            MmeEpsType::DetachRequestToUe,
            "TAU ignored"
        );
        assert!(ue.t3422.is_running());

        let service_request = [0xc7, 0x00, 0x00, 0x00];
        nas_eps_handle_uplink(&ctx, uplink(enb_ue_id, &service_request));
        let ue = ctx.mme_ue_find_by_id(mme_ue_id).unwrap();
        assert_eq!(
            ue.nas_eps.type_,
            MmeEpsType::DetachRequestToUe,
            "SR ignored"
        );
        assert!(ue.t3422.is_running());

        // The DETACH ACCEPT still completes the detach: the context goes.
        let accept = [
            NAS_PROTOCOL_DISCRIMINATOR_EMM,
            NasEpsMessageType::DetachAccept as u8,
        ];
        nas_eps_handle_uplink(&ctx, uplink(enb_ue_id, &accept));
        assert!(ctx.mme_ue_find_by_id(mme_ue_id).is_none());
    }

    /// #828: a CS fallback EXTENDED SERVICE REQUEST (service type 0) during a
    /// re-attach-required detach does not take over the UE: the detach is
    /// progressed (T3422 running, state DetachRequestToUe). Before #828 only
    /// packet-services ESRs reached the collision hook, so this one overwrote
    /// the state and the detach was silently dropped.
    #[test]
    fn a_cs_fallback_extended_service_request_during_a_detach_is_ignored() {
        let ctx = test_ctx();
        let enb_ue_id = enb_with_connection(&ctx);
        let mme_ue_id = ue_with_vector(&ctx, enb_ue_id);
        // A NAS security context, so the protected ESR is accepted.
        nas_eps_handle_uplink(
            &ctx,
            uplink(enb_ue_id, &attach_request(&imsi_identity(), &[])),
        );
        nas_eps_handle_uplink(&ctx, uplink(enb_ue_id, &authentication_response()));
        assert!(
            ctx.mme_ue_find_by_id(mme_ue_id)
                .unwrap()
                .security_context_available
        );
        assert_eq!(
            crate::network_detach::mme_initiated_detach(
                &ctx,
                mme_ue_id,
                crate::emm_build::DetachTypeToUe::ReAttachRequired,
                "test"
            ),
            crate::network_detach::DetachOutcome::DetachRequestSent
        );
        let mme_ue = ctx.mme_ue_find_by_id(mme_ue_id).unwrap();
        let esr = [
            NAS_PROTOCOL_DISCRIMINATOR_EMM,
            emm_type::EXTENDED_SERVICE_REQUEST,
            0x00, // service type 0: mobile originating CS fallback
            0x05,
            0xf4,
            0x00,
            0x00,
            0x00,
            0x01,
        ];
        let protected = protect_uplink(&mme_ue, 2, &esr);
        nas_eps_handle_uplink(&ctx, uplink(enb_ue_id, &protected));
        let ue = ctx.mme_ue_find_by_id(mme_ue_id).unwrap();
        assert_eq!(
            ue.nas_eps.type_,
            MmeEpsType::DetachRequestToUe,
            "ESR ignored"
        );
        assert!(ue.t3422.is_running(), "the detach is progressed");
    }

    /// The decision table of §5.5.2.3.5 d-f, including the EXTENDED SERVICE
    /// REQUEST and IMSI detach rows the dispatch tests do not reach.
    #[test]
    fn the_collision_table_follows_ts_24_301_5_5_2_3_5() {
        use crate::emm_build::DetachTypeToUe as T;
        use crate::network_detach::{on_colliding_procedure, CollidingProcedure as P, Collision};
        for (detach, procedure, expected) in [
            (T::ReAttachRequired, P::Attach, Collision::Proceed),
            (T::ReAttachNotRequired, P::Attach, Collision::Ignore),
            (T::ImsiDetach, P::Attach, Collision::Proceed),
            (
                T::ReAttachRequired,
                P::TrackingAreaUpdate,
                Collision::Ignore,
            ),
            (
                T::ReAttachNotRequired,
                P::TrackingAreaUpdate,
                Collision::Ignore,
            ),
            (T::ImsiDetach, P::TrackingAreaUpdate, Collision::Proceed),
            (T::ReAttachRequired, P::ServiceRequest, Collision::Ignore),
            (T::ReAttachNotRequired, P::ServiceRequest, Collision::Ignore),
            (T::ImsiDetach, P::ServiceRequest, Collision::Ignore),
            (
                T::ReAttachRequired,
                P::CsFallbackServiceRequest,
                Collision::Ignore,
            ),
            (
                T::ReAttachNotRequired,
                P::CsFallbackServiceRequest,
                Collision::Ignore,
            ),
        ] {
            let ctx = test_ctx();
            let (_, mme_ue_id) = ue_in_network_detach(&ctx, detach);
            assert_eq!(
                on_colliding_procedure(&ctx, mme_ue_id, procedure),
                expected,
                "{detach:?} x {procedure:?}"
            );
            let ue = ctx.mme_ue_find_by_id(mme_ue_id).unwrap();
            let aborted = !ue.t3422.is_running();
            let expect_aborted = expected == Collision::Proceed;
            assert_eq!(aborted, expect_aborted, "{detach:?} x {procedure:?}");
        }
        // No detach pending: everything proceeds.
        let ctx = test_ctx();
        let enb_ue_id = enb_with_connection(&ctx);
        let mme_ue_id = ue_with_vector(&ctx, enb_ue_id);
        assert_eq!(
            on_colliding_procedure(&ctx, mme_ue_id, P::Attach),
            Collision::Proceed
        );
    }

    #[test]
    fn test_attach_request_with_imsi_indexes_ue_and_awaits_a_vector() {
        let ctx = test_ctx();
        let enb_ue_id = enb_with_connection(&ctx);
        let pdu = attach_request(&imsi_identity(), &pdn_connectivity_request(1, false));

        nas_eps_handle_uplink(&ctx, uplink(enb_ue_id, &pdu));

        // The EMM attach handler ran: the identity was parsed onto a UE context
        // and indexed, and the ESM container was held for the security context.
        let mme_ue_id = ctx
            .mme_ue_find_by_imsi(TEST_IMSI)
            .expect("attach request must index the UE by IMSI");
        let mme_ue = ctx.mme_ue_find_by_id(mme_ue_id).unwrap();
        assert_eq!(mme_ue.nas_eps.type_, MmeEpsType::AttachRequest);
        assert_eq!(mme_ue.nas_eps.attach_type, 1);
        assert_eq!(mme_ue.ue_network_capability.eea, 0xf0);
        assert_eq!(
            mme_ue.pdn_connectivity_request,
            pdn_connectivity_request(1, false)
        );
        // The S1 connection is bound to the new context.
        assert_eq!(mme_ue.enb_ue_id, enb_ue_id);
        assert_eq!(
            ctx.enb_ue_find_by_id(enb_ue_id).unwrap().mme_ue_id,
            mme_ue_id
        );
        // No vector, so no challenge went out and no identity was requested.
        assert!(mme_ue.t3460.pkbuf.is_none());
        assert!(mme_ue.t3470.pkbuf.is_none());
    }

    #[test]
    fn test_attach_request_with_a_vector_sends_authentication_request() {
        let ctx = test_ctx();
        let enb_ue_id = enb_with_connection(&ctx);
        // A UE context that already holds an HSS vector, as
        // `mme_s6a_handle_aia` would leave it.
        let mme_ue_id = ctx.mme_ue_add(enb_ue_id);
        ctx.enb_ue_associate_mme_ue(enb_ue_id, mme_ue_id);
        {
            let mut pool = ctx.mme_ue_pool.write().unwrap();
            let mme_ue = pool.get_mut(&mme_ue_id).unwrap();
            mme_ue.xres[..8].copy_from_slice(&[0xaa; 8]);
            mme_ue.xres_len = 8;
            mme_ue.rand = [0x11; 16];
            mme_ue.autn = [0x22; 16];
        }
        let pdu = attach_request(&imsi_identity(), &pdn_connectivity_request(1, false));

        nas_eps_handle_uplink(&ctx, uplink(enb_ue_id, &pdu));

        let mme_ue = ctx.mme_ue_find_by_id(mme_ue_id).unwrap();
        assert_eq!(
            emm_message_type(&mme_ue.t3460.pkbuf),
            Some(NasEpsMessageType::AuthenticationRequest as u8),
            "an Authentication Request must be armed on T3460"
        );
    }

    #[test]
    fn test_attach_request_without_identity_sends_identity_request() {
        let ctx = test_ctx();
        let enb_ue_id = enb_with_connection(&ctx);
        // A GUTI that names no context the MME holds.
        let pdu = attach_request(
            &guti_identity(2, 1, 0xc0ff_ee01),
            &pdn_connectivity_request(1, false),
        );

        nas_eps_handle_uplink(&ctx, uplink(enb_ue_id, &pdu));

        let mme_ue_id = ctx.enb_ue_find_by_id(enb_ue_id).unwrap().mme_ue_id;
        let mme_ue = ctx.mme_ue_find_by_id(mme_ue_id).unwrap();
        assert!(mme_ue.imsi_bcd.is_empty());
        assert_eq!(
            emm_message_type(&mme_ue.t3470.pkbuf),
            Some(NasEpsMessageType::IdentityRequest as u8),
            "an Identity Request must be armed on T3470"
        );
    }

    #[test]
    fn test_malformed_attach_request_is_rejected_without_indexing_the_ue() {
        let ctx = test_ctx();
        let enb_ue_id = enb_with_connection(&ctx);
        // Header plus a body far shorter than the mandatory IEs.
        let pdu = vec![
            NAS_PROTOCOL_DISCRIMINATOR_EMM,
            NasEpsMessageType::AttachRequest as u8,
            0x71,
            0x08,
        ];

        nas_eps_handle_uplink(&ctx, uplink(enb_ue_id, &pdu));

        assert!(ctx.mme_ue_find_by_imsi(TEST_IMSI).is_none());
        let mme_ue_id = ctx.enb_ue_find_by_id(enb_ue_id).unwrap().mme_ue_id;
        let mme_ue = ctx.mme_ue_find_by_id(mme_ue_id).unwrap();
        assert!(mme_ue.t3470.pkbuf.is_none());
        assert_released_after_attach_reject(&ctx, enb_ue_id);
    }

    /// TS 24.301 5.3.1.2.1: after an Attach Reject the MME releases the S1 UE
    /// context with NAS cause normal-release -- the UE does not release it itself.
    fn assert_released_after_attach_reject(ctx: &MmeContext, enb_ue_id: u64) {
        let enb_ue = ctx.enb_ue_find_by_id(enb_ue_id).unwrap();
        assert_eq!(
            enb_ue.ue_ctx_rel_action,
            UeCtxRelAction::UeContextRemove,
            "an Attach Reject must be followed by a UE Context Release Command"
        );
        assert_eq!(enb_ue.relcause.group, S1apCauseGroup::Nas);
        assert_eq!(
            enb_ue.relcause.cause,
            nas_cause::NORMAL_RELEASE,
            "the release after a reject is a normal release, not a detach"
        );
    }

    #[test]
    fn test_reattach_replaces_the_stale_context_and_keeps_the_imsi_index() {
        let ctx = test_ctx();
        // First attach.
        let first_enb_ue = enb_with_connection(&ctx);
        let pdu = attach_request(&imsi_identity(), &pdn_connectivity_request(1, false));
        nas_eps_handle_uplink(&ctx, uplink(first_enb_ue, &pdu));
        let first_mme_ue = ctx.mme_ue_find_by_imsi(TEST_IMSI).unwrap();

        // The same subscriber attaches again on a fresh S1 connection.
        let enb_id = ctx.enb_ue_find_by_id(first_enb_ue).unwrap().enb_id;
        let second_enb_ue = ctx.enb_ue_add(enb_id, 101);
        nas_eps_handle_uplink(&ctx, uplink(second_enb_ue, &pdu));

        // The index must point at the surviving context, not be left dangling by
        // the stale context's removal.
        let second_mme_ue = ctx
            .mme_ue_find_by_imsi(TEST_IMSI)
            .expect("the IMSI index must survive the implicit detach");
        assert_ne!(second_mme_ue, first_mme_ue);
        assert_eq!(
            ctx.mme_ue_find_by_id(second_mme_ue).unwrap().enb_ue_id,
            second_enb_ue
        );
        assert!(
            ctx.mme_ue_find_by_id(first_mme_ue).is_none(),
            "the stale context must be implicitly detached"
        );
    }

    /// #488's scenario through the real NAS path: a UE that received ATTACH REJECT
    /// keeps its EPS security context (TS 24.301 §5.5.1.2.5) and re-attaches on a
    /// NEW NAS signalling connection. The MME implicitly detached the old context
    /// (§5.5.1.2.4), so it holds no security context, and the UE's AUTHENTICATION
    /// RESPONSE arrives integrity protected with the context the network no longer
    /// has. §4.4.4.3 lists AUTHENTICATION RESPONSE among the messages processed
    /// without a secure exchange, and NOTE 3 names exactly this case ("protected
    /// with an EPS security context that is no longer available in the network").
    /// The MME must authenticate and proceed to the SECURITY MODE COMMAND.
    fn reattach_to_a_fresh_context(ctx: &MmeContext) -> (u64, u64) {
        let first_enb_ue = enb_with_connection(ctx);
        let attach = attach_request(&imsi_identity(), &pdn_connectivity_request(1, false));
        nas_eps_handle_uplink(ctx, uplink(first_enb_ue, &attach));
        let first_mme_ue = ctx.mme_ue_find_by_imsi(TEST_IMSI).unwrap();
        {
            // The first attach had taken a context into use.
            let mut pool = ctx.mme_ue_pool.write().unwrap();
            pool.get_mut(&first_mme_ue)
                .unwrap()
                .security_context_available = true;
        }

        let enb_id = ctx.enb_ue_find_by_id(first_enb_ue).unwrap().enb_id;
        let second_enb_ue = ctx.enb_ue_add(enb_id, 102);
        nas_eps_handle_uplink(ctx, uplink(second_enb_ue, &attach));
        let mme_ue_id = ctx.mme_ue_find_by_imsi(TEST_IMSI).unwrap();
        assert_ne!(
            mme_ue_id, first_mme_ue,
            "the old context is implicitly detached"
        );
        {
            // A fresh vector for the re-attach, as the AIA would deliver.
            let mut pool = ctx.mme_ue_pool.write().unwrap();
            let mme_ue = pool.get_mut(&mme_ue_id).unwrap();
            assert!(!mme_ue.security_context_available);
            mme_ue.xres[..8].copy_from_slice(&[0xaa; 8]);
            mme_ue.xres_len = 8;
            mme_ue.rand = [0x11; 16];
            mme_ue.autn = [0x22; 16];
            mme_ue.kasme = [0x44; 32];
        }
        (second_enb_ue, mme_ue_id)
    }

    #[test]
    fn test_reattach_auth_response_protected_with_the_old_context_is_processed() {
        let ctx = test_ctx();
        let (enb_ue_id, mme_ue_id) = reattach_to_a_fresh_context(&ctx);

        // Integrity protected (header type 1) with a MAC the MME cannot verify.
        let mut pdu = vec![0x17, 0xde, 0xad, 0xbe, 0xef, 0x03];
        pdu.extend_from_slice(&authentication_response());
        nas_eps_handle_uplink(&ctx, uplink(enb_ue_id, &pdu));

        let mme_ue = ctx.mme_ue_find_by_id(mme_ue_id).unwrap();
        assert_eq!(
            protected_message_type(&mme_ue.t3460.pkbuf),
            Some(NasEpsMessageType::SecurityModeCommand as u8),
            "authentication must complete and the SECURITY MODE COMMAND go out"
        );
    }

    /// The same re-attach with the AUTHENTICATION RESPONSE CIPHERED (header type 2).
    /// TS 24.301 §4.4.5: the UE starts ciphering "when the secure exchange of NAS
    /// messages has been established for a NAS signalling connection", and the
    /// re-attach is a NEW connection — the MME released the old one after the
    /// ATTACH REJECT (#473). A ciphered message here is a UE fault, and its body is
    /// unreadable without the context, so it is discarded and no procedure runs.
    #[test]
    fn test_reattach_auth_response_ciphered_with_the_old_context_is_discarded() {
        let ctx = test_ctx();
        let (enb_ue_id, mme_ue_id) = reattach_to_a_fresh_context(&ctx);

        let mut pdu = vec![0x27, 0xde, 0xad, 0xbe, 0xef, 0x03];
        pdu.extend_from_slice(&authentication_response());
        nas_eps_handle_uplink(&ctx, uplink(enb_ue_id, &pdu));

        let mme_ue = ctx.mme_ue_find_by_id(mme_ue_id).unwrap();
        assert_ne!(
            protected_message_type(&mme_ue.t3460.pkbuf),
            Some(NasEpsMessageType::SecurityModeCommand as u8)
        );
        assert!(!mme_ue.security_context_available);
    }

    #[test]
    fn test_s_tmsi_reassociates_an_existing_ue_context() {
        let ctx = test_ctx();
        // A context holding the GUTI the UE is using. Nothing allocates GUTIs
        // yet (#46), so it is seeded here.
        let old_enb_ue = enb_with_connection(&ctx);
        let mme_ue_id = ctx.mme_ue_add(old_enb_ue);
        ctx.enb_ue_associate_mme_ue(old_enb_ue, mme_ue_id);
        ctx.mme_ue_set_imsi(mme_ue_id, TEST_IMSI);
        {
            let mut pool = ctx.mme_ue_pool.write().unwrap();
            let mme_ue = pool.get_mut(&mme_ue_id).unwrap();
            mme_ue.current.m_tmsi = Some(0xc0ff_ee01);
            mme_ue.current.guti.mme_code = 1;
        }

        let enb_id = ctx.enb_ue_find_by_id(old_enb_ue).unwrap().enb_id;
        let new_enb_ue = ctx.enb_ue_add(enb_id, 101);
        let ue_count_before = ctx.mme_ue_pool.read().unwrap().len();

        nas_eps_handle_uplink(
            &ctx,
            UplinkNas {
                enb_ue_id: new_enb_ue,
                // Body is immaterial: resolution happens before dispatch.
                nas_pdu: &[NAS_PROTOCOL_DISCRIMINATOR_EMM, 0x00],
                s_tmsi: Some((1, 0xc0ff_ee01)),
            },
        );

        assert_eq!(
            ctx.mme_ue_pool.read().unwrap().len(),
            ue_count_before,
            "the S-TMSI must be re-associated, not allocate a second context"
        );
        assert_eq!(
            ctx.enb_ue_find_by_id(new_enb_ue).unwrap().mme_ue_id,
            mme_ue_id
        );
    }

    /// #481, TS 24.301 §4.4.4.3: a UE that kept its EPS security context after
    /// the network dropped it re-attaches integrity protected. The MAC cannot be
    /// verified, but ATTACH REQUEST is on the list the MME processes anyway; the
    /// attach path then authenticates. It used to be silently discarded, and the
    /// UE was never answered on any T3411 retry.
    #[test]
    fn test_protected_attach_without_a_security_context_is_processed() {
        let ctx = test_ctx();
        let enb_ue_id = enb_with_connection(&ctx);
        // Integrity-protected header (type 1) wrapping an Attach Request.
        let mut pdu = vec![0x17, 0xde, 0xad, 0xbe, 0xef, 0x01];
        pdu.extend_from_slice(&attach_request(
            &imsi_identity(),
            &pdn_connectivity_request(1, false),
        ));

        nas_eps_handle_uplink(&ctx, uplink(enb_ue_id, &pdu));

        let mme_ue_id = ctx
            .mme_ue_find_by_imsi(TEST_IMSI)
            .expect("the protected Attach Request must be processed (TS 24.301 4.4.4.3)");
        let mme_ue = ctx.mme_ue_find_by_id(mme_ue_id).unwrap();
        assert_eq!(mme_ue.nas_eps.type_, MmeEpsType::AttachRequest);
        assert!(
            !mme_ue.security_context_available,
            "processing it must not invent a security context"
        );
    }

    /// A CIPHERED message cannot be read without the context, so it is still
    /// discarded even when it is an ATTACH REQUEST.
    #[test]
    fn test_ciphered_message_without_a_security_context_is_discarded() {
        let ctx = test_ctx();
        let enb_ue_id = enb_with_connection(&ctx);
        let mut pdu = vec![0x27, 0xde, 0xad, 0xbe, 0xef, 0x01];
        pdu.extend_from_slice(&attach_request(
            &imsi_identity(),
            &pdn_connectivity_request(1, false),
        ));

        nas_eps_handle_uplink(&ctx, uplink(enb_ue_id, &pdu));

        assert!(ctx.mme_ue_find_by_imsi(TEST_IMSI).is_none());
    }

    /// Only the §4.4.4.3 list, only integrity-protected headers, only whole PDUs.
    #[test]
    fn test_unverifiable_but_processable_is_limited_to_the_exempt_list() {
        let attach = attach_request(&imsi_identity(), &pdn_connectivity_request(1, false));
        let mut prot = vec![0x17, 0, 0, 0, 0, 1];
        prot.extend_from_slice(&attach);
        assert_eq!(unverifiable_but_processable(1, &prot), Some(attach.clone()));
        assert_eq!(unverifiable_but_processable(3, &prot), Some(attach.clone()));
        assert_eq!(unverifiable_but_processable(2, &prot), None, "ciphered");
        assert_eq!(
            unverifiable_but_processable(4, &prot),
            None,
            "ciphered, new context"
        );
        // ATTACH COMPLETE is not on the list.
        let mut complete = vec![0x17, 0, 0, 0, 0, 1];
        complete.extend_from_slice(&[
            NAS_PROTOCOL_DISCRIMINATOR_EMM,
            NasEpsMessageType::AttachComplete as u8,
            0,
            0,
        ]);
        assert_eq!(unverifiable_but_processable(1, &complete), None);
        // A protected ESM message is never exempt by this route.
        let mut esm = vec![0x17, 0, 0, 0, 0, 1];
        esm.extend_from_slice(&pdn_connectivity_request(1, false));
        assert_eq!(unverifiable_but_processable(1, &esm), None);
        // Truncated.
        assert_eq!(unverifiable_but_processable(1, &prot[..7]), None);
    }

    #[test]
    fn test_mac_failure_on_attach_processes_it_and_clears_the_flag() {
        let ctx = test_ctx();
        let enb_ue_id = enb_with_connection(&ctx);
        let mme_ue_id = ctx.mme_ue_add(enb_ue_id);
        ctx.enb_ue_associate_mme_ue(enb_ue_id, mme_ue_id);
        {
            let mut pool = ctx.mme_ue_pool.write().unwrap();
            let mme_ue = pool.get_mut(&mme_ue_id).unwrap();
            mme_ue.security_context_available = true;
            mme_ue.selected_int_algorithm = 2; // EIA2
            mme_ue.knas_int = [0x33; 16];
        }
        // Integrity-protected, MAC deliberately wrong.
        let mut pdu = vec![0x17, 0x00, 0x00, 0x00, 0x00, 0x01];
        pdu.extend_from_slice(&attach_request(
            &imsi_identity(),
            &pdn_connectivity_request(1, false),
        ));

        nas_eps_handle_uplink(&ctx, uplink(enb_ue_id, &pdu));

        // TS 24.301 §4.4.4.3: an ATTACH REQUEST that fails the integrity check is
        // processed, and the MME authenticates before going further (#481).
        assert_eq!(
            ctx.mme_ue_find_by_imsi(TEST_IMSI),
            Some(mme_ue_id),
            "a MAC-failed Attach Request must still be processed"
        );
        let mme_ue = ctx.mme_ue_find_by_id(mme_ue_id).unwrap();
        assert_eq!(mme_ue.nas_eps.type_, MmeEpsType::AttachRequest);
        assert!(
            !mme_ue.mac_failed,
            "the failure flag must not leak into the next message"
        );
    }

    #[test]
    fn test_identity_response_indexes_the_imsi() {
        let ctx = test_ctx();
        let enb_ue_id = enb_with_connection(&ctx);
        let identity = imsi_identity();
        let mut pdu = vec![
            NAS_PROTOCOL_DISCRIMINATOR_EMM,
            NasEpsMessageType::IdentityResponse as u8,
            identity.len() as u8,
        ];
        pdu.extend_from_slice(&identity);

        nas_eps_handle_uplink(&ctx, uplink(enb_ue_id, &pdu));

        assert!(
            ctx.mme_ue_find_by_imsi(TEST_IMSI).is_some(),
            "the identity response must index the UE"
        );
    }

    #[test]
    fn test_authentication_response_selects_algorithms_and_derives_keys() {
        let ctx = test_ctx();
        let enb_ue_id = enb_with_connection(&ctx);
        let mme_ue_id = ue_with_vector(&ctx, enb_ue_id);

        nas_eps_handle_uplink(&ctx, uplink(enb_ue_id, &authentication_response()));

        let mme_ue = ctx.mme_ue_find_by_id(mme_ue_id).unwrap();
        // The shipped configuration's order is [EIA2, EIA1, EIA0] and
        // [EEA0, EEA1, EEA2], and this UE supports 0-3.
        assert_eq!(mme_ue.selected_int_algorithm, 2, "EIA2 must be selected");
        assert_eq!(
            mme_ue.selected_enc_algorithm, 0,
            "EEA0 is what the shipped ciphering order asks for first"
        );
        // TS 33.401 Annex A.7 keys, derived for exactly those algorithms.
        assert_eq!(
            mme_ue.knas_int,
            nextgcore_crypt::kdf::nextgcore_kdf_nas_eps(
                nas_security::NAS_INT_ALG_DISTINGUISHER,
                2,
                &[0x44; 32]
            )
        );
        assert_eq!(
            mme_ue.knas_enc,
            nextgcore_crypt::kdf::nextgcore_kdf_nas_eps(
                nas_security::NAS_ENC_ALG_DISTINGUISHER,
                0,
                &[0x44; 32]
            )
        );
        assert_ne!(mme_ue.knas_int, [0u8; 16], "the keys must not be null");
        assert_eq!(
            protected_message_type(&mme_ue.t3460.pkbuf),
            Some(NasEpsMessageType::SecurityModeCommand as u8),
            "a Security Mode Command must be armed on T3460"
        );
        // Non-null integrity means the command carries a real MAC.
        let smc = mme_ue.t3460.pkbuf.clone().unwrap();
        assert_ne!(&smc[1..5], &[0u8; 4], "the MAC must not be null");
        // Selected NAS security algorithms IE: EEA in the high nibble, EIA in
        // the low one, so EEA0/EIA2 is 0x02.
        assert_eq!(
            smc[8], 0x02,
            "the command must carry the selected EEA0/EIA2"
        );
        assert!(mme_ue.security_context_available);
    }

    #[test]
    fn test_no_common_integrity_algorithm_rejects_the_attach() {
        let ctx = test_ctx();
        let enb_ue_id = enb_with_connection(&ctx);
        let mme_ue_id = ue_with_vector(&ctx, enb_ue_id);
        {
            // A UE advertising EIA0 only: TS 33.401 5.1.4.1 allows null
            // integrity for unauthenticated emergency calls only.
            let mut pool = ctx.mme_ue_pool.write().unwrap();
            pool.get_mut(&mme_ue_id).unwrap().ue_network_capability.eia = 0x80;
        }

        nas_eps_handle_uplink(&ctx, uplink(enb_ue_id, &authentication_response()));

        let mme_ue = ctx.mme_ue_find_by_id(mme_ue_id).unwrap();
        assert_eq!(
            mme_ue.selected_int_algorithm, 0,
            "no algorithm may be taken into use"
        );
        assert_eq!(mme_ue.knas_int, [0u8; 16], "no keys may be derived");
        assert!(
            mme_ue.t3460.pkbuf.is_none(),
            "no Security Mode Command may go out; the attach is rejected instead"
        );
        assert_released_after_attach_reject(&ctx, enb_ue_id);
    }

    /// #480, TS 33.401 Annex A.3: SECURITY MODE COMPLETE takes the NAS context
    /// into use, and K_eNB = HMAC-SHA256(K_ASME, 0x11 || UL NAS COUNT || 0x0004)
    /// with the COUNT of that SECURITY MODE COMPLETE. The expected keys were
    /// computed with an independent HMAC-SHA256, not with nextgcore-crypt. Before,
    /// nothing derived K_eNB, and the INITIAL CONTEXT SETUP carried zeros.
    #[test]
    fn security_mode_complete_derives_kenb_from_its_ul_count() {
        for (kasme, sqn, expected) in [
            (
                core::array::from_fn::<u8, 32, _>(|i| i as u8),
                0u8,
                "e6267359de012d9bda173d1b6fae57dec0e04e01cfcf57cb33a7573f142b8b95",
            ),
            (
                [0x5a; 32],
                3u8,
                "4bc069d9dea0c817703932ee49453db68b557317a08fd587cde7714b840d97ec",
            ),
        ] {
            let ctx = test_ctx();
            let enb_ue_id = enb_with_connection(&ctx);
            let mme_ue_id = ue_with_vector(&ctx, enb_ue_id);
            nas_eps_handle_uplink(&ctx, uplink(enb_ue_id, &authentication_response()));
            {
                let mut pool = ctx.mme_ue_pool.write().unwrap();
                let mme_ue = pool.get_mut(&mme_ue_id).unwrap();
                mme_ue.kasme = kasme;
                mme_ue.nhcc = 5; // stale chain from an earlier context
                mme_ue.nh = [0xee; 32];
            }
            let mme_ue = ctx.mme_ue_find_by_id(mme_ue_id).unwrap();
            let complete = protect_uplink(
                &mme_ue,
                sqn,
                &[
                    NAS_PROTOCOL_DISCRIMINATOR_EMM,
                    NasEpsMessageType::SecurityModeComplete as u8,
                ],
            );
            nas_eps_handle_uplink(&ctx, uplink(enb_ue_id, &complete));

            let mme_ue = ctx.mme_ue_find_by_id(mme_ue_id).unwrap();
            assert!(mme_ue.security_context_available);
            let hex: String = mme_ue.kenb.iter().map(|b| format!("{b:02x}")).collect();
            assert_eq!(hex, expected, "K_eNB for UL NAS COUNT {sqn}");
            assert_eq!(mme_ue.nhcc, 0, "the NH chain restarts from the new K_eNB");
            assert_eq!(mme_ue.nh, [0; 32]);
        }
    }

    #[test]
    fn test_protected_uplink_round_trip_completes_the_security_procedure() {
        let ctx = test_ctx();
        let enb_ue_id = enb_with_connection(&ctx);
        let mme_ue_id = ue_with_vector(&ctx, enb_ue_id);
        {
            let mut pool = ctx.mme_ue_pool.write().unwrap();
            let mme_ue = pool.get_mut(&mme_ue_id).unwrap();
            mme_ue.nas_eps.type_ = MmeEpsType::AttachRequest;
            mme_ue.pdn_connectivity_request = pdn_connectivity_request(5, false);
        }

        // Authentication Response -> real Security Mode Command.
        nas_eps_handle_uplink(&ctx, uplink(enb_ue_id, &authentication_response()));

        // The UE answers with an integrity-protected SECURITY MODE COMPLETE,
        // MAC'd with the key both sides now hold.
        let mme_ue = ctx.mme_ue_find_by_id(mme_ue_id).unwrap();
        let complete = protect_uplink(
            &mme_ue,
            1,
            &[
                NAS_PROTOCOL_DISCRIMINATOR_EMM,
                NasEpsMessageType::SecurityModeComplete as u8,
            ],
        );
        nas_eps_handle_uplink(&ctx, uplink(enb_ue_id, &complete));

        let mme_ue = ctx.mme_ue_find_by_id(mme_ue_id).unwrap();
        assert_eq!(mme_ue.ul_count, 1, "the verified message advanced UL COUNT");
        assert!(
            mme_ue.pdn_connectivity_request.is_empty(),
            "the held ESM container must be consumed"
        );
        // The container reached the ESM entity through a verified message.
        let sess_id = ctx
            .sess_find_by_pti(mme_ue_id, 5)
            .expect("the ESM handler must have created the session");
        let sess = ctx.sess_find_by_id(sess_id).unwrap();
        assert_eq!(sess.apn, TEST_APN);
        assert_eq!(sess.ue_request_pdn_type, PdnType::Ipv4);
    }

    #[test]
    fn test_protected_standalone_esm_reaches_the_esm_entity() {
        let ctx = test_ctx();
        let enb_ue_id = enb_with_connection(&ctx);
        let mme_ue_id = ue_with_vector(&ctx, enb_ue_id);
        nas_eps_handle_uplink(&ctx, uplink(enb_ue_id, &authentication_response()));

        // A standalone ESM message under a security header: the outer header
        // carries the EMM protocol discriminator, the inner message ESM's
        // (TS 24.301 9.3), so the dispatch must route on the INNER one.
        let mme_ue = ctx.mme_ue_find_by_id(mme_ue_id).unwrap();
        let request = protect_uplink(&mme_ue, 1, &pdn_connectivity_request(3, true));
        nas_eps_handle_uplink(&ctx, uplink(enb_ue_id, &request));

        // TS 24.301 6.5.1.2: the transfer flag with no APN means the UE will
        // send them separately, so the MME asks.
        let sess_id = ctx.sess_find_by_pti(mme_ue_id, 3).expect("session created");
        let bearer_id = ctx.sess_find_by_id(sess_id).unwrap().bearer_list[0];
        let bearer = ctx.bearer_find_by_id(bearer_id).unwrap();
        assert!(
            bearer.t3489.pkbuf.is_some(),
            "an ESM Information Request must be armed on T3489"
        );
    }

    #[test]
    fn test_unprotected_messages_outside_the_allowlist_are_discarded() {
        let ctx = test_ctx();
        let enb_ue_id = enb_with_connection(&ctx);
        let mme_ue_id = ue_with_vector(&ctx, enb_ue_id);
        {
            let mut pool = ctx.mme_ue_pool.write().unwrap();
            pool.get_mut(&mme_ue_id).unwrap().pdn_connectivity_request =
                pdn_connectivity_request(5, false);
        }

        // SECURITY MODE COMPLETE is always protected with the new context, so a
        // plain copy must not be processed (TS 24.301 4.4.4.2).
        nas_eps_handle_uplink(
            &ctx,
            uplink(
                enb_ue_id,
                &[
                    NAS_PROTOCOL_DISCRIMINATOR_EMM,
                    NasEpsMessageType::SecurityModeComplete as u8,
                ],
            ),
        );
        let mme_ue = ctx.mme_ue_find_by_id(mme_ue_id).unwrap();
        assert!(!mme_ue.security_context_available);
        assert!(!mme_ue.pdn_connectivity_request.is_empty());

        // A standalone unprotected ESM message must not reach the ESM entity.
        nas_eps_handle_uplink(&ctx, uplink(enb_ue_id, &pdn_connectivity_request(9, false)));
        assert!(ctx.sess_find_by_pti(mme_ue_id, 9).is_none());

        // An allowlisted message still is: this one a UE has no key for.
        nas_eps_handle_uplink(&ctx, uplink(enb_ue_id, &authentication_response()));
        assert!(
            ctx.mme_ue_find_by_id(mme_ue_id)
                .unwrap()
                .t3460
                .pkbuf
                .is_some(),
            "an ATTACH/AUTHENTICATION-class message may arrive unprotected"
        );
    }

    /// #702: a SERVICE REQUEST the MME cannot verify is rejected with #9 AND its S1
    /// connection released (NAS normal-release), so the UE re-attaches at once
    /// instead of after its own T3440.
    #[test]
    fn test_a_service_reject_releases_the_s1_connection() {
        let ctx = test_ctx();
        let enb_ue_id = enb_with_connection(&ctx);
        let mme_ue_id = ctx.mme_ue_add(enb_ue_id);
        ctx.enb_ue_associate_mme_ue(enb_ue_id, mme_ue_id);

        // Security header type 12 (SERVICE REQUEST), KSI 0 / seq 1, short MAC.
        // No security context exists for this UE, so it cannot be verified (#9).
        let pdu = vec![0xC7, 0x01, 0xAB, 0xCD];
        nas_eps_handle_uplink(&ctx, uplink(enb_ue_id, &pdu));

        let enb_ue = ctx.enb_ue_find_by_id(enb_ue_id).unwrap();
        assert_eq!(
            enb_ue.ue_ctx_rel_action,
            UeCtxRelAction::UeContextRemove,
            "the S1 connection must be released after SERVICE REJECT"
        );
        assert_eq!(enb_ue.relcause.group, S1apCauseGroup::Nas);
        assert_eq!(enb_ue.relcause.cause, s1ap_build::nas_cause::NORMAL_RELEASE);
    }

    /// #688: DETACH ACCEPT completes a network-initiated detach: T3422 stops
    /// and the UE context is removed with the S1 connection.
    #[test]
    fn test_detach_accept_completes_a_network_initiated_detach() {
        let ctx = test_ctx();
        let enb_ue_id = enb_with_connection(&ctx);
        let mme_ue_id = ctx.mme_ue_add(enb_ue_id);
        ctx.enb_ue_associate_mme_ue(enb_ue_id, mme_ue_id);
        ctx.mme_ue_set_imsi(mme_ue_id, TEST_IMSI);
        let out = crate::network_detach::mme_initiated_detach(
            &ctx,
            mme_ue_id,
            crate::emm_build::DetachTypeToUe::ReAttachRequired,
            "test",
        );
        assert_eq!(out, crate::network_detach::DetachOutcome::DetachRequestSent);

        let pdu = vec![
            NAS_PROTOCOL_DISCRIMINATOR_EMM,
            NasEpsMessageType::DetachAccept as u8,
        ];
        nas_eps_handle_uplink(&ctx, uplink(enb_ue_id, &pdu));

        assert!(ctx.mme_ue_find_by_id(mme_ue_id).is_none());
        assert!(ctx.mme_ue_find_by_imsi(TEST_IMSI).is_none());
        assert_eq!(
            ctx.enb_ue_find_by_id(enb_ue_id).unwrap().ue_ctx_rel_action,
            UeCtxRelAction::UeContextRemove
        );
    }

    /// #689: after an SGW-restart detach completes, the same UE's re-attach
    /// (on a new S1 connection, carrying its old S-TMSI) gets a fresh context
    /// and goes on to authentication; the old context does not come back.
    #[test]
    fn test_a_re_attach_after_an_sgw_restart_detach_starts_afresh() {
        let ctx = test_ctx();
        let enb_ue_id = enb_with_connection(&ctx);
        let old = ctx.mme_ue_add(enb_ue_id);
        ctx.enb_ue_associate_mme_ue(enb_ue_id, old);
        ctx.mme_ue_set_imsi(old, TEST_IMSI);
        ctx.set_sgw_s11_teid_for_ue(old, 0x11);
        // The S-TMSI the old attach assigned (no served GUMMEI in a test context).
        if let Some(ue) = ctx.mme_ue_pool.write().unwrap().get_mut(&old) {
            ue.current.m_tmsi = Some(0x689);
            ue.current.guti.mme_code = 1;
        }
        assert_eq!(ctx.mme_ue_find_by_s_tmsi(1, 0x689), Some(old));
        let sgw: std::net::SocketAddr = "10.10.4.41:2123".parse().unwrap();
        assert_eq!(
            crate::network_detach::sgw_restarted(&ctx, Some(sgw), sgw.ip()),
            1
        );
        nas_eps_handle_uplink(
            &ctx,
            uplink(
                enb_ue_id,
                &[
                    NAS_PROTOCOL_DISCRIMINATOR_EMM,
                    NasEpsMessageType::DetachAccept as u8,
                ],
            ),
        );
        assert!(ctx.mme_ue_find_by_id(old).is_none());

        let enb_id = ctx.enb_add("127.0.0.2:36412".parse().unwrap());
        let new_conn = ctx.enb_ue_add(enb_id, 101);
        let pdu = attach_request(&imsi_identity(), &pdn_connectivity_request(1, false));
        nas_eps_handle_uplink(
            &ctx,
            UplinkNas {
                enb_ue_id: new_conn,
                nas_pdu: &pdu,
                s_tmsi: Some((1, 0x689)),
            },
        );
        let fresh = ctx
            .mme_ue_find_by_imsi(TEST_IMSI)
            .expect("re-attach indexed");
        assert_ne!(fresh, old);
        let ue = ctx.mme_ue_find_by_id(fresh).unwrap();
        assert_eq!(ue.nas_eps.type_, MmeEpsType::AttachRequest);
        assert_eq!(ue.enb_ue_id, new_conn, "the new S1 connection's context");
    }

    #[test]
    fn test_detach_request_removes_the_ue_context() {
        let ctx = test_ctx();
        let enb_ue_id = enb_with_connection(&ctx);
        let mme_ue_id = ctx.mme_ue_add(enb_ue_id);
        ctx.enb_ue_associate_mme_ue(enb_ue_id, mme_ue_id);
        ctx.mme_ue_set_imsi(mme_ue_id, TEST_IMSI);

        let pdu = vec![
            NAS_PROTOCOL_DISCRIMINATOR_EMM,
            NasEpsMessageType::DetachRequest as u8,
            0x09, // detach type 1, switch off
        ];
        nas_eps_handle_uplink(&ctx, uplink(enb_ue_id, &pdu));

        assert!(ctx.mme_ue_find_by_id(mme_ue_id).is_none());
        assert!(ctx.mme_ue_find_by_imsi(TEST_IMSI).is_none());
        assert_eq!(
            ctx.enb_ue_find_by_id(enb_ue_id).unwrap().ue_ctx_rel_action,
            UeCtxRelAction::UeContextRemove,
            "the S1 connection must be marked for release"
        );
    }

    #[test]
    fn test_attach_without_a_vector_queues_an_s6a_request() {
        let ctx = test_ctx();
        let enb_ue_id = enb_with_connection(&ctx);
        let pdu = attach_request(&imsi_identity(), &pdn_connectivity_request(1, false));

        // No queue is installed in a unit test, so the request is dropped and
        // reported. What matters here is that the dispatch ASKS -- before this
        // landed it logged a dead end -- and that a dropped request leaves the UE
        // exactly as it was rather than half-advancing the procedure.
        nas_eps_handle_uplink(&ctx, uplink(enb_ue_id, &pdu));

        let mme_ue_id = ctx.mme_ue_find_by_imsi(TEST_IMSI).expect("UE indexed");
        let mme_ue = ctx.mme_ue_find_by_id(mme_ue_id).unwrap();
        assert_eq!(mme_ue.xres_len, 0, "no vector may be invented");
        assert!(
            mme_ue.t3460.pkbuf.is_none(),
            "no challenge goes out until a vector arrives"
        );
        assert!(!mme_ue.security_context_available);
    }

    #[test]
    fn test_security_mode_complete_requests_subscription_data() {
        let ctx = test_ctx();
        let enb_ue_id = enb_with_connection(&ctx);
        let mme_ue_id = ue_with_vector(&ctx, enb_ue_id);
        {
            let mut pool = ctx.mme_ue_pool.write().unwrap();
            let mme_ue = pool.get_mut(&mme_ue_id).unwrap();
            mme_ue.nas_eps.type_ = MmeEpsType::AttachRequest;
        }
        nas_eps_handle_uplink(&ctx, uplink(enb_ue_id, &authentication_response()));

        let mme_ue = ctx.mme_ue_find_by_id(mme_ue_id).unwrap();
        let complete = protect_uplink(
            &mme_ue,
            1,
            &[
                NAS_PROTOCOL_DISCRIMINATOR_EMM,
                NasEpsMessageType::SecurityModeComplete as u8,
            ],
        );
        nas_eps_handle_uplink(&ctx, uplink(enb_ue_id, &complete));

        // No queue is installed in a unit test, so the request is dropped and
        // reported; what matters is that the procedure now ASKS, and that no
        // subscription is invented while it waits.
        let mme_ue = ctx.mme_ue_find_by_id(mme_ue_id).unwrap();
        assert!(mme_ue.security_context_available);
        assert_eq!(mme_ue.num_of_session, 0, "no subscription may be invented");
        assert_eq!(mme_ue.ambr.uplink, 0);
    }

    #[test]
    fn test_update_location_queue_helper_reports_a_dropped_request() {
        assert!(!crate::fd_path::queue_update_location(4242, true));
    }

    #[test]
    fn test_queue_helper_reports_a_dropped_request() {
        // The sync side must never fail its caller's procedure, so an absent
        // queue is a `false` return and a log line, not a panic.
        assert!(!crate::fd_path::queue_authentication_information(4242));
    }

    #[test]
    fn test_truncated_res_does_not_establish_a_security_context() {
        let ctx = test_ctx();
        let enb_ue_id = enb_with_connection(&ctx);
        let mme_ue_id = ue_with_vector(&ctx, enb_ue_id);

        // A one-octet RES matching the first octet of the seeded XRES (0xaa).
        let mut pdu = vec![
            NAS_PROTOCOL_DISCRIMINATOR_EMM,
            NasEpsMessageType::AuthenticationResponse as u8,
            0x01,
        ];
        pdu.push(0xaa);
        nas_eps_handle_uplink(&ctx, uplink(enb_ue_id, &pdu));

        let mme_ue = ctx.mme_ue_find_by_id(mme_ue_id).unwrap();
        assert!(
            !mme_ue.security_context_available,
            "a truncated RES must not authenticate the UE"
        );
        assert_eq!(mme_ue.selected_int_algorithm, 0);
        assert_eq!(mme_ue.knas_int, [0u8; 16]);
        assert!(
            mme_ue.t3460.pkbuf.is_none(),
            "no Security Mode Command is due"
        );
    }

    #[test]
    fn test_synch_failure_stores_the_auts_and_stops_t3460() {
        let ctx = test_ctx();
        let enb_ue_id = enb_with_connection(&ctx);
        let mme_ue_id = ue_with_vector(&ctx, enb_ue_id);
        // An outstanding AUTHENTICATION REQUEST.
        {
            let mut pool = ctx.mme_ue_pool.write().unwrap();
            let mme_ue = pool.get_mut(&mme_ue_id).unwrap();
            mme_ue.t3460.pkbuf = Some(vec![0x07, 0x52]);
            mme_ue.t3460.start(crate::nas_timer::T3460_DURATION);
        }

        let auts = [0x5a; 14];
        let mut pdu = vec![
            NAS_PROTOCOL_DISCRIMINATOR_EMM,
            NasEpsMessageType::AuthenticationFailure as u8,
            21,   // EMM cause #21, synch failure
            0x30, // Authentication Failure Parameter
            14,
        ];
        pdu.extend_from_slice(&auts);
        nas_eps_handle_uplink(&ctx, uplink(enb_ue_id, &pdu));

        let mme_ue = ctx.mme_ue_find_by_id(mme_ue_id).unwrap();
        assert_eq!(
            mme_ue.resync_auts,
            Some(auts),
            "the AUTS must be kept for the re-synchronisation AIR"
        );
        assert_eq!(mme_ue.xres_len, 0, "the rejected vector must be discarded");
        assert!(!mme_ue.t3460.is_running(), "T3460 must be stopped");
        assert!(mme_ue.t3460.pkbuf.is_none());
    }

    #[test]
    fn test_mac_failure_re_identifies_the_ue() {
        let ctx = test_ctx();
        let enb_ue_id = enb_with_connection(&ctx);
        let mme_ue_id = ue_with_vector(&ctx, enb_ue_id);

        let pdu = vec![
            NAS_PROTOCOL_DISCRIMINATOR_EMM,
            NasEpsMessageType::AuthenticationFailure as u8,
            20, // EMM cause #20, MAC failure
        ];
        nas_eps_handle_uplink(&ctx, uplink(enb_ue_id, &pdu));

        let mme_ue = ctx.mme_ue_find_by_id(mme_ue_id).unwrap();
        assert_eq!(mme_ue.xres_len, 0, "the rejected vector must be discarded");
        assert_eq!(
            emm_message_type(&mme_ue.t3470.pkbuf),
            Some(NasEpsMessageType::IdentityRequest as u8),
            "TS 24.301 5.4.2.7 e): the network may re-identify the UE"
        );
        assert!(mme_ue.t3470.is_running(), "T3470 must be armed");
        // The IMSI index still resolves: clearing imsi_bcd would strand it.
        assert_eq!(ctx.mme_ue_find_by_imsi(TEST_IMSI), Some(mme_ue_id));
    }

    #[test]
    fn test_completing_messages_stop_their_timers() {
        let ctx = test_ctx();
        let enb_ue_id = enb_with_connection(&ctx);
        let mme_ue_id = ue_with_vector(&ctx, enb_ue_id);

        // Identity Response stops T3470.
        {
            let mut pool = ctx.mme_ue_pool.write().unwrap();
            let mme_ue = pool.get_mut(&mme_ue_id).unwrap();
            mme_ue.t3470.pkbuf = Some(vec![0x07, 0x55, 0x01]);
            mme_ue.t3470.start(crate::nas_timer::T3470_DURATION);
        }
        let identity = imsi_identity();
        let mut pdu = vec![
            NAS_PROTOCOL_DISCRIMINATOR_EMM,
            NasEpsMessageType::IdentityResponse as u8,
            identity.len() as u8,
        ];
        pdu.extend_from_slice(&identity);
        nas_eps_handle_uplink(&ctx, uplink(enb_ue_id, &pdu));
        let mme_ue = ctx.mme_ue_find_by_id(mme_ue_id).unwrap();
        assert!(!mme_ue.t3470.is_running());
        assert!(mme_ue.t3470.pkbuf.is_none());

        // Authentication Response stops T3460 (and arms it again for the
        // Security Mode Command it sends, which is a different procedure step).
        nas_eps_handle_uplink(&ctx, uplink(enb_ue_id, &authentication_response()));
        let mme_ue = ctx.mme_ue_find_by_id(mme_ue_id).unwrap();
        assert_eq!(
            protected_message_type(&mme_ue.t3460.pkbuf),
            Some(NasEpsMessageType::SecurityModeCommand as u8)
        );
        assert_eq!(mme_ue.t3460.retry_count, 0, "a fresh procedure starts at 0");

        // Security Mode Complete stops T3460 for good.
        let complete = protect_uplink(
            &mme_ue,
            1,
            &[
                NAS_PROTOCOL_DISCRIMINATOR_EMM,
                NasEpsMessageType::SecurityModeComplete as u8,
            ],
        );
        nas_eps_handle_uplink(&ctx, uplink(enb_ue_id, &complete));
        let mme_ue = ctx.mme_ue_find_by_id(mme_ue_id).unwrap();
        assert!(!mme_ue.t3460.is_running());
        assert!(mme_ue.t3460.pkbuf.is_none());
    }

    /// #46 criterion 4 and 5: a GUTI Reallocation Complete promotes the staged GUTI so
    /// the UE becomes resolvable by S-TMSI.
    ///
    /// 0x51 shared an arm with TAU Complete before #46 and neither committed anything,
    /// so the acknowledgement was recorded and the new identity never took effect.
    #[test]
    fn guti_reallocation_complete_commits_the_staged_guti() {
        // Its OWN context with a served GUMMEI: `test_ctx()` has none, and adding one
        // there would change the ambient state every other test in this module runs
        // against.
        let mut ctx = test_ctx();
        ctx.served_gummei = vec![crate::context::ServedGummei {
            num_of_plmn_id: 1,
            plmn_id: vec![crate::context::PlmnId::new("001", "01")],
            num_of_mme_gid: 1,
            mme_gid: vec![2],
            num_of_mme_code: 1,
            mme_code: vec![1],
        }];
        ctx.num_of_served_gummei = 1;
        let ctx = ctx;
        let enb_ue_id = enb_with_connection(&ctx);
        let mme_ue_id = ue_with_vector(&ctx, enb_ue_id);
        nas_eps_handle_uplink(&ctx, uplink(enb_ue_id, &authentication_response()));

        assert!(
            ctx.allocate_guti(mme_ue_id),
            "the fixture's served GUMMEI must allow an allocation"
        );
        let staged = ctx
            .mme_ue_find_by_id(mme_ue_id)
            .unwrap()
            .next
            .m_tmsi
            .expect("staged");
        let mme_code = ctx.mme_ue_find_by_id(mme_ue_id).unwrap().next.guti.mme_code;
        assert_eq!(
            ctx.mme_ue_find_by_s_tmsi(mme_code, staged),
            None,
            "a staged GUTI must not resolve before the UE acknowledges it"
        );

        let mme_ue = ctx.mme_ue_find_by_id(mme_ue_id).unwrap();
        let complete = protect_uplink(
            &mme_ue,
            1,
            &[
                NAS_PROTOCOL_DISCRIMINATOR_EMM,
                NasEpsMessageType::GutiReallocationComplete as u8,
            ],
        );
        nas_eps_handle_uplink(&ctx, uplink(enb_ue_id, &complete));

        assert_eq!(
            ctx.mme_ue_find_by_s_tmsi(mme_code, staged),
            Some(mme_ue_id),
            "the acknowledged GUTI must resolve the UE by S-TMSI"
        );
    }

    /// #956, TS 24.301 §5.5.1.2.4: ATTACH COMPLETE makes the GUTI of the ATTACH
    /// ACCEPT valid, so the UE is resolvable by its S-TMSI when it returns from
    /// ECM-IDLE (SERVICE REQUEST, paging response).
    #[test]
    fn attach_complete_commits_the_staged_guti() {
        // Its OWN context with a served GUMMEI: `test_ctx()` has none, and adding one
        // there would change the ambient state every other test in this module runs
        // against.
        let mut ctx = test_ctx();
        ctx.served_gummei = vec![crate::context::ServedGummei {
            num_of_plmn_id: 1,
            plmn_id: vec![crate::context::PlmnId::new("001", "01")],
            num_of_mme_gid: 1,
            mme_gid: vec![2],
            num_of_mme_code: 1,
            mme_code: vec![1],
        }];
        ctx.num_of_served_gummei = 1;
        let ctx = ctx;
        let enb_ue_id = enb_with_connection(&ctx);
        let mme_ue_id = ue_with_vector(&ctx, enb_ue_id);
        nas_eps_handle_uplink(&ctx, uplink(enb_ue_id, &authentication_response()));

        assert!(
            ctx.allocate_guti(mme_ue_id),
            "the fixture's served GUMMEI must allow an allocation"
        );
        let staged = ctx
            .mme_ue_find_by_id(mme_ue_id)
            .unwrap()
            .next
            .m_tmsi
            .expect("staged");
        let mme_code = ctx.mme_ue_find_by_id(mme_ue_id).unwrap().next.guti.mme_code;
        assert_eq!(
            ctx.mme_ue_find_by_s_tmsi(mme_code, staged),
            None,
            "a staged GUTI must not resolve before the UE acknowledges it"
        );

        let mme_ue = ctx.mme_ue_find_by_id(mme_ue_id).unwrap();
        let complete = protect_uplink(
            &mme_ue,
            1,
            &[
                NAS_PROTOCOL_DISCRIMINATOR_EMM,
                NasEpsMessageType::AttachComplete as u8,
                0x00,
                0x00,
            ],
        );
        nas_eps_handle_uplink(&ctx, uplink(enb_ue_id, &complete));

        assert_eq!(
            ctx.mme_ue_find_by_s_tmsi(mme_code, staged),
            Some(mme_ue_id),
            "the acknowledged GUTI must resolve the UE by S-TMSI"
        );
    }

    #[test]
    fn test_attach_complete_stops_t3450() {
        let ctx = test_ctx();
        let enb_ue_id = enb_with_connection(&ctx);
        let mme_ue_id = ue_with_vector(&ctx, enb_ue_id);
        nas_eps_handle_uplink(&ctx, uplink(enb_ue_id, &authentication_response()));
        {
            // An outstanding ATTACH ACCEPT.
            let mut pool = ctx.mme_ue_pool.write().unwrap();
            let mme_ue = pool.get_mut(&mme_ue_id).unwrap();
            mme_ue.t3450.pkbuf = Some(vec![0x07, 0x42]);
            mme_ue.t3450.start(crate::nas_timer::T3450_DURATION);
        }

        // ATTACH COMPLETE carrying a two-octet ESM container length of 0.
        let mme_ue = ctx.mme_ue_find_by_id(mme_ue_id).unwrap();
        let complete = protect_uplink(
            &mme_ue,
            1,
            &[
                NAS_PROTOCOL_DISCRIMINATOR_EMM,
                NasEpsMessageType::AttachComplete as u8,
                0x00,
                0x00,
            ],
        );
        nas_eps_handle_uplink(&ctx, uplink(enb_ue_id, &complete));

        let mme_ue = ctx.mme_ue_find_by_id(mme_ue_id).unwrap();
        assert!(!mme_ue.t3450.is_running(), "T3450 must be stopped");
        assert!(
            mme_ue.t3450.pkbuf.is_none(),
            "the stored accept is discarded"
        );
    }

    #[test]
    fn test_security_mode_reject_aborts_and_releases() {
        let ctx = test_ctx();
        let enb_ue_id = enb_with_connection(&ctx);
        let mme_ue_id = ue_with_vector(&ctx, enb_ue_id);
        nas_eps_handle_uplink(&ctx, uplink(enb_ue_id, &authentication_response()));

        let pdu = vec![
            NAS_PROTOCOL_DISCRIMINATOR_EMM,
            NasEpsMessageType::SecurityModeReject as u8,
            24, // EMM cause #24, security mode rejected unspecified
        ];
        nas_eps_handle_uplink(&ctx, uplink(enb_ue_id, &pdu));

        let mme_ue = ctx.mme_ue_find_by_id(mme_ue_id).unwrap();
        assert!(!mme_ue.t3460.is_running());
        assert_eq!(
            ctx.enb_ue_find_by_id(enb_ue_id).unwrap().ue_ctx_rel_action,
            UeCtxRelAction::UeContextRemove,
            "TS 24.301 5.4.3.5 releases the NAS signalling connection"
        );
    }

    #[test]
    fn test_rejected_esm_request_hands_back_its_session() {
        let ctx = test_ctx();
        let enb_ue_id = enb_with_connection(&ctx);
        let mme_ue_id = ue_with_vector(&ctx, enb_ue_id);
        nas_eps_handle_uplink(&ctx, uplink(enb_ue_id, &authentication_response()));

        // A PDN CONNECTIVITY REQUEST with no body at all, so not even the
        // mandatory PDN type / request type octet: protected and verified, but
        // the ESM handler refuses it. (A single octet is a VALID minimal request,
        // TS 24.301 Table 8.3.20.1 -- this test used to call that malformed, #481.)
        let mme_ue = ctx.mme_ue_find_by_id(mme_ue_id).unwrap();
        let malformed = protect_uplink(
            &mme_ue,
            1,
            &[
                NAS_PROTOCOL_DISCRIMINATOR_ESM,
                7, // procedure transaction identity
                EsmMessageType::PdnConnectivityRequest as u8,
            ],
        );
        nas_eps_handle_uplink(&ctx, uplink(enb_ue_id, &malformed));

        // The contexts the rejected request allocated are handed back rather
        // than accumulating.
        assert!(ctx.sess_find_by_pti(mme_ue_id, 7).is_none());
        assert!(ctx.sess_pool.read().unwrap().is_empty());
        assert!(ctx.bearer_pool.read().unwrap().is_empty());
        assert!(ctx
            .mme_ue_find_by_id(mme_ue_id)
            .unwrap()
            .sess_list
            .is_empty());
    }

    // ------------------------------------------------------------------
    // The attach path's S11 Create Session Request (#329)
    // ------------------------------------------------------------------

    /// The criterion this issue exists for: driving a real PDN Connectivity Request
    /// through the NAS dispatch makes a Create Session Request reach the wire.
    ///
    /// Before #329 this branch logged "the S11 Create Session Request to the SGW is not
    /// implemented (#51)" and returned — so `gtp_path::send_create_session_request` had
    /// no caller at all and no attach could complete. A test that called the sender
    /// directly would have passed against that state, which is why this one starts from
    /// an uplink NAS PDU.
    ///
    /// It is also the ONLY test in this crate that installs the process-wide S11 server:
    /// `S11_SERVER` is a `OnceLock`, so a second installer would silently use the
    /// first's socket and assert about a sibling's traffic. It therefore also carries
    /// the correlation assertions, rather than leaving those to a second install.
    #[test]
    fn the_pdn_connectivity_path_sends_a_create_session_request() {
        use nextgcore_gtp::v2::{Gtp2IeType, Gtp2Message};

        let _guard = crate::gtp_path::lock_s11();
        crate::gtp_path::clear_pending_creates_for_test();

        // A stand-in SGW-C that only receives, plus the MME's real S11 socket.
        let peer = std::net::UdpSocket::bind("127.0.0.1:0").expect("peer bind");
        peer.set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .expect("peer timeout");
        let peer_addr = peer.local_addr().expect("peer addr");
        let server = crate::gtp_path::GtpcServer::open(
            "127.0.0.1:0",
            nextgcore_gtp::v2::xact::Gtp2XactConfig::default(),
            7,
        )
        .expect("S11 bind");
        if !crate::gtp_path::install_server(server) {
            // A sibling installed first; this test would then be asserting about that
            // socket rather than its own. Skipped rather than made flaky.
            return;
        }

        let mut ctx = test_ctx();
        ctx.sgwc_list = vec![peer_addr];
        let enb_ue_id = enb_with_connection(&ctx);
        let mme_ue_id = ue_with_vector(&ctx, enb_ue_id);

        // A real ATTACH REQUEST first, so the UE's EMM procedure IS an attach. Without
        // it `mme_ue.nas_eps.type_` is unset and the create action derives to
        // `UplinkNasTransport` — correct for a standalone PDN connectivity request, but
        // not the path this issue is about.
        nas_eps_handle_uplink(
            &ctx,
            uplink(
                enb_ue_id,
                &attach_request(&[0x08, 0x29, 0x43, 0x65, 0x87, 0x09, 0x21, 0x43], &[]),
            ),
        );

        // Establish the security context the ESM handler requires.
        nas_eps_handle_uplink(&ctx, uplink(enb_ue_id, &authentication_response()));
        assert!(
            ctx.mme_ue_find_by_id(mme_ue_id)
                .unwrap()
                .security_context_available,
            "precondition: the ESM handler refuses without a security context"
        );

        // A well-formed PDN CONNECTIVITY REQUEST: PDN type IPv4 (high nibble 1) and
        // request type 1 (initial request), then an APN IE so the request is complete
        // and does NOT divert into an ESM Information Request instead.
        let mme_ue = ctx.mme_ue_find_by_id(mme_ue_id).unwrap();
        let mut esm = vec![
            NAS_PROTOCOL_DISCRIMINATOR_ESM,
            7, // procedure transaction identity
            EsmMessageType::PdnConnectivityRequest as u8,
            0x11, // PDN type IPv4 | request type 1
            0x28, // Access Point Name IEI
        ];
        let apn = b"\x08internet";
        esm.push(apn.len() as u8);
        esm.extend_from_slice(apn);
        let protected = protect_uplink(&mme_ue, 1, &esm);

        nas_eps_handle_uplink(&ctx, uplink(enb_ue_id, &protected));

        // #479, TS 23.401 §5.3.2.1: the Create Session Request is step 12, AFTER
        // the Update Location Answer (step 11) — it is built from the
        // subscription. Nothing may reach the SGW-C before it.
        peer.set_read_timeout(Some(std::time::Duration::from_millis(300)))
            .expect("peer timeout");
        let mut buf = [0u8; 4096];
        assert!(
            peer.recv_from(&mut buf).is_err(),
            "no Create Session Request may be sent before the ULA (#479)"
        );
        peer.set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .expect("peer timeout");

        // The ULA arrives through the real continuation, subscribing APN
        // `internet`.
        crate::fd_path::on_update_location_answer(
            &ctx,
            mme_ue_id,
            Ok(crate::fd_path::UlaMessage {
                result_code: 2001,
                subscription_data: crate::fd_path::SubscriptionData {
                    ambr_uplink: 100_000_000,
                    ambr_downlink: 200_000_000,
                    apn_configs: vec![crate::fd_path::ApnConfiguration {
                        context_identifier: 1,
                        service_selection: "internet".to_string(),
                        pdn_type: 0, // IPv4
                        qci: 9,
                        arp_priority_level: 8,
                        ambr_uplink: 50_000_000,
                        ambr_downlink: 100_000_000,
                        ..Default::default()
                    }],
                    ..Default::default()
                },
                ..Default::default()
            }),
        );

        // The CSR must now be on the wire.
        let (len, _) = peer
            .recv_from(&mut buf)
            .expect("a Create Session Request must reach the SGW-C");
        let mut bytes = bytes::Bytes::copy_from_slice(&buf[..len]);
        let received = Gtp2Message::decode(&mut bytes).expect("the CSR must decode");
        assert_eq!(
            received.header.message_type,
            crate::s11_build::message_type::CREATE_SESSION_REQUEST,
            "the NAS path must send a Create Session Request, not some other message"
        );

        // #479: the IMSI IE carries the subscriber's TBCD octets (TS 29.274 §8.3),
        // not fifteen zeros.
        let imsi_bcd = ctx.mme_ue_find_by_id(mme_ue_id).unwrap().imsi_bcd;
        let imsi = received
            .get_ie(Gtp2IeType::Imsi as u8, 0)
            .expect("IMSI is mandatory");
        assert_eq!(
            imsi.value.as_ref(),
            crate::n26_build::string_to_bcd(&imsi_bcd).as_slice(),
            "the IMSI must be TBCD-encoded from {imsi_bcd}"
        );
        assert!(imsi.value.iter().any(|b| *b != 0));

        // #479: PAA present, requesting dynamic IPv4 allocation (§8.14).
        let paa = received
            .get_ie(Gtp2IeType::Paa as u8, 0)
            .expect("PAA must be present for an E-UTRAN initial attach");
        assert_eq!(paa.value.as_ref(), &[1u8, 0, 0, 0, 0]);

        // The subscribed APN, paired with the UE's request.
        let apn = received.get_ie(Gtp2IeType::Apn as u8, 0).expect("APN");
        assert_eq!(apn.value.as_ref(), b"\x08internet");

        // The Sender F-TEID must carry a REAL S11 TEID. Before #329 `mme_s11_teid` was
        // never assigned, so this was 0 and no response could be attributed to a UE.
        let fteid = nextgcore_gtp::v2::Gtp2FTeidIe::decode(
            &received
                .get_ie(Gtp2IeType::FTeid as u8, 0)
                .expect("Sender F-TEID is mandatory")
                .value,
        )
        .expect("the F-TEID must decode");
        assert_ne!(
            fteid.teid, 0,
            "the Sender F-TEID must name a real TEID: 0 is the pre-#329 value and \\
             mme_s11_teid_hash cannot resolve it"
        );
        assert_eq!(
            ctx.mme_ue_find_by_s11_local_teid(fteid.teid),
            Some(mme_ue_id),
            "and that TEID must resolve back to this UE, which is what lets the \\
             Create Session Response be attributed"
        );

        // The pending record must be keyed by the sequence number that went out, and
        // must name an ATTACH (the UE's EMM procedure), so the response continues to an
        // Attach Accept rather than to nothing.
        let pending = crate::gtp_path::take_pending_create(received.header.sequence_number)
            .expect("the wire sequence number must be the record's key");
        assert_eq!(
            pending.create_action,
            crate::s11_build::GtpCreateAction::AttachRequest
        );
        assert_eq!(pending.enb_ue_id, enb_ue_id);

        // #727, TS 29.274 §7.6: an initial Request that is not a Command has the
        // sequence number's MSB clear, and both Commands this MME sends have it set
        // (so the SGW's own initial Requests can never close them). Asserted here
        // because this is the only test that may install the process-wide socket.
        assert!(
            !nextgcore_gtp::v2::is_command_sequence(received.header.sequence_number),
            "the Create Session Request is not a Command: {:#x}",
            received.header.sequence_number
        );
        let mut recv_command = |expected: u8| {
            let (len, _) = peer.recv_from(&mut buf).expect("the Command must be sent");
            let mut bytes = bytes::Bytes::copy_from_slice(&buf[..len]);
            let msg = Gtp2Message::decode(&mut bytes).expect("the Command must decode");
            assert_eq!(msg.header.message_type, expected);
            msg.header.sequence_number
        };
        let dbc_seq = crate::gtp_path::send_delete_bearer_command(&ctx, mme_ue_id, &[5])
            .expect("Delete Bearer Command sent");
        let wire = recv_command(nextgcore_gtp::v2::Gtp2MessageType::DeleteBearerCommand as u8);
        assert_eq!(wire, dbc_seq);
        assert!(
            nextgcore_gtp::v2::is_command_sequence(wire),
            "the Delete Bearer Command's number has the MSB set: {wire:#x}"
        );
        let bearer_id = crate::gtp_path::bearers_of_ue(&ctx, mme_ue_id)
            .first()
            .expect("the attach created the default bearer")
            .id;
        crate::gtp_path::send_bearer_resource_command(&ctx, bearer_id, 5, 9, &[0x01], None)
            .expect("Bearer Resource Command sent");
        let wire = recv_command(nextgcore_gtp::v2::Gtp2MessageType::BearerResourceCommand as u8);
        assert!(
            nextgcore_gtp::v2::is_command_sequence(wire),
            "the Bearer Resource Command's number has the MSB set: {wire:#x}"
        );

        crate::gtp_path::clear_pending_creates_for_test();
    }

    #[test]
    fn test_unknown_protocol_discriminator_is_discarded() {
        let ctx = test_ctx();
        let enb_ue_id = enb_with_connection(&ctx);

        nas_eps_handle_uplink(&ctx, uplink(enb_ue_id, &[0x0f, 0x41, 0x00]));

        // A UE context is still resolved (the S1 connection is real), but no
        // procedure ran.
        let mme_ue_id = ctx.enb_ue_find_by_id(enb_ue_id).unwrap().mme_ue_id;
        let mme_ue = ctx.mme_ue_find_by_id(mme_ue_id).unwrap();
        assert_eq!(mme_ue.nas_eps.type_, MmeEpsType::None);
    }

    #[test]
    fn test_short_and_unknown_contexts_are_ignored() {
        let ctx = test_ctx();
        let enb_ue_id = enb_with_connection(&ctx);

        // Too short to hold a NAS header.
        nas_eps_handle_uplink(&ctx, uplink(enb_ue_id, &[0x07]));
        // No such S1 connection.
        nas_eps_handle_uplink(&ctx, uplink(9999, &[0x07, 0x41]));

        assert!(ctx.mme_ue_pool.read().unwrap().is_empty());
    }
}
