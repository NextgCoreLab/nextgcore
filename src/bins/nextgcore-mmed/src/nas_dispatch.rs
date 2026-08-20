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
use crate::nas_path::{self, GtpCreateAction};
use crate::nas_security::{self, SecurityHeaderTypeFlags};
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
        NAS_PROTOCOL_DISCRIMINATOR_EMM => dispatch_emm(ctx, &enb_ue, mme_ue_id, uplink.nas_pdu),
        NAS_PROTOCOL_DISCRIMINATOR_ESM => {
            // An ESM message may arrive standalone (TS 24.301 §8.3), not only
            // piggybacked in an EMM container.
            let Some(mme_ue) = ctx.mme_ue_find_by_id(mme_ue_id) else {
                return;
            };
            handle_esm_message(ctx, &enb_ue, &mme_ue, uplink.nas_pdu);
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
    // Nothing allocates GUTIs yet (#46), so `current.m_tmsi` is never set and
    // this lookup cannot hit in production today. It is implemented rather than
    // skipped so the path is correct the moment GUTI allocation lands.
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

fn dispatch_emm(ctx: &MmeContext, enb_ue: &EnbUe, mme_ue_id: u64, pdu: &[u8]) {
    let security_header_type = pdu[0] >> 4;

    if security_header_type >= SERVICE_REQUEST_HEADER_TYPE {
        emm_service_request(ctx, enb_ue, mme_ue_id, pdu);
        return;
    }

    let plain = if security_header_type == 0 {
        pdu.to_vec()
    } else {
        match decode_protected(ctx, mme_ue_id, security_header_type, pdu) {
            Some(plain) => plain,
            None => return,
        }
    };

    if plain.len() < 2 {
        log::warn!("Decoded EMM message too short ({} bytes)", plain.len());
        return;
    }

    let message_type = plain[1];
    let body = &plain[2..];

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
        emm_type::TAU_REQUEST => emm_tau_request(ctx, enb_ue, mme_ue_id, body),
        emm_type::EXTENDED_SERVICE_REQUEST => {
            emm_extended_service_request(ctx, enb_ue, mme_ue_id, body);
        }
        emm_type::DETACH_REQUEST => emm_detach_request(ctx, enb_ue, mme_ue_id, body),
        emm_type::AUTHENTICATION_FAILURE => {
            // AUTS resynchronisation and MAC-failure handling are #45.
            log::warn!(
                "Authentication Failure from enb_ue_s1ap_id={} (EMM cause #{}); AUTS \
                 resynchronisation is not implemented (#45)",
                enb_ue.enb_ue_s1ap_id,
                body.first().copied().unwrap_or(0)
            );
        }
        emm_type::SECURITY_MODE_REJECT => {
            // TS 24.301 §5.4.3.5: the network aborts the procedure.
            log::error!(
                "Security Mode Reject from enb_ue_s1ap_id={} (EMM cause #{}); aborting the \
                 security mode control procedure",
                enb_ue.enb_ue_s1ap_id,
                body.first().copied().unwrap_or(0)
            );
        }
        emm_type::DETACH_ACCEPT => {
            log::info!(
                "Detach Accept from enb_ue_s1ap_id={}; releasing the S1 connection",
                enb_ue.enb_ue_s1ap_id
            );
            release_ue_context(ctx, enb_ue);
        }
        emm_type::TAU_COMPLETE | emm_type::GUTI_REALLOCATION_COMPLETE => {
            log::debug!(
                "EMM 0x{message_type:02x} acknowledged by enb_ue_s1ap_id={}",
                enb_ue.enb_ue_s1ap_id
            );
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
fn decode_protected(
    ctx: &MmeContext,
    mme_ue_id: u64,
    security_header_type: u8,
    pdu: &[u8],
) -> Option<Vec<u8>> {
    let flags = SecurityHeaderTypeFlags::from_header_type(security_header_type);
    let mut message = pdu.to_vec();

    let mut pool = ctx.mme_ue_pool.write().unwrap();
    let mme_ue = pool.get_mut(&mme_ue_id)?;

    // TS 24.301 §4.4.4.2: a protected message can only be processed against an
    // existing NAS security context. `nas_eps_security_decode` answers `Ok` for
    // a context-less UE with the security header still attached, so without
    // this guard the header bytes would be misread as the message body.
    if !mme_ue.security_context_available {
        log::warn!(
            "[{}] Security-protected NAS (header type {security_header_type}) from a UE with no \
             security context; discarded",
            mme_ue.imsi_bcd
        );
        return None;
    }

    if let Err(e) = nas_security::nas_eps_security_decode(mme_ue, flags, &mut message) {
        log::warn!("[{}] NAS security decode failed: {e}", mme_ue.imsi_bcd);
        return None;
    }

    // TS 24.301 §4.4.4.3: a message that fails the integrity check is
    // discarded. `mac_failed` is cleared so it cannot leak into the next
    // message on this context.
    if std::mem::take(&mut mme_ue.mac_failed) {
        log::warn!(
            "[{}] NAS integrity check failed; message discarded",
            mme_ue.imsi_bcd
        );
        return None;
    }

    // The security header is only stripped when an algorithm is actually in
    // use, and NAS algorithm selection is not implemented (#44). Rather than
    // read a MAC octet as a message type, insist the decode produced a plain
    // EMM header (TS 24.301 §9.3.1: security header type 0, PD 0x07).
    if message.first() != Some(&NAS_PROTOCOL_DISCRIMINATOR_EMM) {
        log::warn!(
            "[{}] NAS security decode left a protected message (first octet {:#04x}); discarded — \
             no NAS algorithm is selected (#44)",
            mme_ue.imsi_bcd,
            message.first().copied().unwrap_or(0)
        );
        return None;
    }

    Some(message)
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
            Ok(esm_message) => esm_message,
            Err(e) => {
                log::warn!("[{}] Attach Complete rejected: {e}", mme_ue.imsi_bcd);
                return;
            }
        }
    };

    // TS 24.301 §5.5.1.2.4: the ESM container carries ACTIVATE DEFAULT EPS
    // BEARER CONTEXT ACCEPT, which belongs to the ESM entity.
    forward_to_esm(ctx, enb_ue, mme_ue_id, &esm_message);
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
            // context into use.
            mme_ue.t3460.pkbuf = None;
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
        mme_ue.t3460.pkbuf = None;
        // Replay the container held since Attach Request, now that
        // `security_context_available` is set (TS 24.301 §5.5.1.2.2).
        std::mem::take(&mut mme_ue.pdn_connectivity_request)
    };

    if held_esm.is_empty() {
        return;
    }
    forward_to_esm(ctx, enb_ue, mme_ue_id, &held_esm);
}

fn emm_tau_request(ctx: &MmeContext, enb_ue: &EnbUe, mme_ue_id: u64, body: &[u8]) {
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
    // No E-RABs can be listed: bearers are established over S11, which is not
    // implemented (#51). The accept therefore never asks for Initial Context
    // Setup, and subscribed timer / GUTI reallocation content is #46.
    if let Err(e) = nas_path::nas_eps_send_tau_accept(mme_ue, enb_ue, false, &[]) {
        log::error!("[{}] TAU Accept send failed: {e}", mme_ue.imsi_bcd);
    }
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
        return;
    }

    // Re-establishing the radio bearers is the Initial Context Setup path (#47).
    log::info!(
        "[{}] SERVICE REQUEST accepted; Initial Context Setup for the active bearers is not \
         implemented (#47)",
        mme_ue.imsi_bcd
    );
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

    log::info!(
        "[{}] EXTENDED SERVICE REQUEST (service_type={service_type}) accepted; CSFB bearer \
         handling is out of scope here",
        mme_ue.imsi_bcd
    );
}

fn emm_detach_request(ctx: &MmeContext, enb_ue: &EnbUe, mme_ue_id: u64, body: &[u8]) {
    {
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

        // TS 24.301 §5.5.2.2.2: no DETACH ACCEPT is sent when the UE detached
        // because it is switching off — it is no longer listening.
        if !switch_off {
            if let Err(e) = nas_path::nas_eps_send_detach_accept(mme_ue, enb_ue) {
                log::error!("[{}] Detach Accept send failed: {e}", mme_ue.imsi_bcd);
            }
        }
    }

    // TS 23.401 §5.3.8.2.1: the MME releases the UE context and the S1
    // connection once the detach procedure completes, switch-off or not.
    ctx.mme_ue_remove(mme_ue_id);
    release_ue_context(ctx, enb_ue);
}

/// Send an authentication challenge, or say why it cannot be sent.
fn authenticate(ctx: &MmeContext, enb_ue: &EnbUe, mme_ue_id: u64) {
    let mut pool = ctx.mme_ue_pool.write().unwrap();
    let Some(mme_ue) = pool.get_mut(&mme_ue_id) else {
        return;
    };

    if mme_ue.xres_len == 0 {
        // Vectors reach the context only through `s6a_handler::mme_s6a_handle_aia`,
        // and mmed never connects its S6a peer: `mme_fd_connect` has no caller and
        // the daemon parses no config, so it has no HSS address. Report it instead
        // of rejecting the UE for a network-side gap or inventing a vector.
        log::warn!(
            "[{}] Attach: no authentication vector — an S6a AIR to the HSS is required and \
             mmed's S6a peer is not connected",
            mme_ue.imsi_bcd
        );
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
        ctx.mme_ue_remove(stale_id);
        if let Some(stale_enb_ue) = stale_enb_ue.and_then(|id| ctx.enb_ue_find_by_id(id)) {
            release_ue_context(ctx, &stale_enb_ue);
        }
    }

    ctx.mme_ue_set_imsi(mme_ue_id, imsi_bcd);
}

/// Ask the eNB to release a UE-associated logical S1 connection.
///
/// The eNB answers `UE CONTEXT RELEASE COMPLETE`, which
/// `s1ap_handler::handle_ue_context_release_complete` turns into the local
/// teardown — so the contexts are not dropped here.
fn release_ue_context(ctx: &MmeContext, enb_ue: &EnbUe) {
    if let Some(stored) = ctx.enb_ue_pool.write().unwrap().get_mut(&enb_ue.id) {
        stored.ue_ctx_rel_action = UeCtxRelAction::UeContextRemove;
        stored.relcause.group = S1apCauseGroup::Nas;
        stored.relcause.cause = nas_cause::DETACH;
    }

    match s1ap_build::build_ue_context_release_command(
        Some(enb_ue.enb_ue_s1ap_id),
        enb_ue.mme_ue_s1ap_id,
        S1apCauseGroup::Nas,
        nas_cause::DETACH,
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

                    log::info!(
                        "[{}] PDN connectivity accepted locally; the S11 Create Session Request \
                         to the SGW is not implemented (#51)",
                        mme_ue.imsi_bcd
                    );
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
                        &sess, mme_ue, enb_ue, esm_cause, gtp_action,
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
                    log::info!(
                        "[{}] ESM information complete; the S11 Create Session Request to the \
                         SGW is not implemented (#51)",
                        mme_ue.imsi_bcd
                    );
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
                Ok(()) => log::info!(
                    "[{}] Dedicated EPS bearer (ebi={}) activated by the UE",
                    mme_ue.imsi_bcd,
                    bearer.ebi
                ),
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
                Ok(cause) => log::warn!(
                    "[{}] Dedicated EPS bearer rejected by the UE: {cause:?}",
                    mme_ue.imsi_bcd
                ),
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
                Ok(()) => log::info!(
                    "[{}] EPS bearer (ebi={}) modification accepted by the UE",
                    mme_ue.imsi_bcd,
                    bearer.ebi
                ),
                Err(e) => log::warn!("[{}] Modify accept rejected: {e}", mme_ue.imsi_bcd),
            }
        }
        esm_type::MODIFY_BEARER_REJECT => {
            match esm_handler::handle_modify_bearer_context_reject(
                enb_ue, mme_ue, &sess, &bearer, body,
            ) {
                Ok(cause) => log::warn!(
                    "[{}] EPS bearer modification rejected by the UE: {cause:?}",
                    mme_ue.imsi_bcd
                ),
                Err(e) => log::warn!("[{}] Modify reject malformed: {e}", mme_ue.imsi_bcd),
            }
        }
        esm_type::DEACTIVATE_BEARER_ACCEPT => {
            match esm_handler::handle_deactivate_bearer_context_accept(
                enb_ue, mme_ue, &sess, &bearer, body,
            ) {
                Ok(()) => log::info!(
                    "[{}] EPS bearer (ebi={}) deactivated by the UE",
                    mme_ue.imsi_bcd,
                    bearer.ebi
                ),
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

/// Send ESM INFORMATION REQUEST, arming T3489's retransmission buffer.
fn send_esm_information_request(ctx: &MmeContext, enb_ue: &EnbUe, mme_ue: &MmeUe, bearer_id: u64) {
    let mut pool = ctx.bearer_pool.write().unwrap();
    let Some(bearer) = pool.get_mut(&bearer_id) else {
        return;
    };
    log::info!(
        "[{}] Requesting ESM information (APN/PCO) from the UE",
        mme_ue.imsi_bcd
    );
    if let Err(e) = nas_path::nas_eps_send_esm_information_request(bearer, mme_ue, enb_ue) {
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

    #[test]
    fn test_protected_message_without_a_security_context_is_discarded() {
        let ctx = test_ctx();
        let enb_ue_id = enb_with_connection(&ctx);
        // Integrity-protected header (type 1) wrapping an Attach Request.
        let mut pdu = vec![0x17, 0xde, 0xad, 0xbe, 0xef, 0x01];
        pdu.extend_from_slice(&attach_request(
            &imsi_identity(),
            &pdn_connectivity_request(1, false),
        ));

        nas_eps_handle_uplink(&ctx, uplink(enb_ue_id, &pdu));

        assert!(
            ctx.mme_ue_find_by_imsi(TEST_IMSI).is_none(),
            "a protected message must not be parsed without a security context"
        );
    }

    #[test]
    fn test_mac_failure_discards_the_message_and_clears_the_flag() {
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

        let mme_ue = ctx.mme_ue_find_by_id(mme_ue_id).unwrap();
        assert!(mme_ue.imsi_bcd.is_empty(), "the message must be discarded");
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
    fn test_authentication_response_match_sends_security_mode_command() {
        let ctx = test_ctx();
        let enb_ue_id = enb_with_connection(&ctx);
        let mme_ue_id = ctx.mme_ue_add(enb_ue_id);
        ctx.enb_ue_associate_mme_ue(enb_ue_id, mme_ue_id);
        {
            let mut pool = ctx.mme_ue_pool.write().unwrap();
            let mme_ue = pool.get_mut(&mme_ue_id).unwrap();
            mme_ue.xres[..8].copy_from_slice(&[0xaa; 8]);
            mme_ue.xres_len = 8;
        }
        let mut pdu = vec![
            NAS_PROTOCOL_DISCRIMINATOR_EMM,
            NasEpsMessageType::AuthenticationResponse as u8,
            0x08,
        ];
        pdu.extend_from_slice(&[0xaa; 8]);

        nas_eps_handle_uplink(&ctx, uplink(enb_ue_id, &pdu));

        let mme_ue = ctx.mme_ue_find_by_id(mme_ue_id).unwrap();
        assert!(
            mme_ue.t3460.pkbuf.is_some(),
            "a Security Mode Command must be armed on T3460"
        );
        assert!(
            mme_ue.security_context_available,
            "encoding the Security Mode Command establishes the security context"
        );
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
    fn test_security_mode_complete_replays_the_held_esm_container() {
        let ctx = test_ctx();
        let enb_ue_id = enb_with_connection(&ctx);
        let mme_ue_id = ctx.mme_ue_add(enb_ue_id);
        ctx.enb_ue_associate_mme_ue(enb_ue_id, mme_ue_id);
        ctx.mme_ue_set_imsi(mme_ue_id, TEST_IMSI);
        {
            let mut pool = ctx.mme_ue_pool.write().unwrap();
            let mme_ue = pool.get_mut(&mme_ue_id).unwrap();
            mme_ue.nas_eps.type_ = MmeEpsType::AttachRequest;
            mme_ue.pdn_connectivity_request = pdn_connectivity_request(5, false);
        }

        // Plain SECURITY MODE COMPLETE: no security context is established, so
        // it arrives unprotected in this test and only the dispatch is exercised.
        let pdu = vec![
            NAS_PROTOCOL_DISCRIMINATOR_EMM,
            NasEpsMessageType::SecurityModeComplete as u8,
        ];
        nas_eps_handle_uplink(&ctx, uplink(enb_ue_id, &pdu));

        let mme_ue = ctx.mme_ue_find_by_id(mme_ue_id).unwrap();
        assert!(mme_ue.security_context_available);
        assert!(
            mme_ue.pdn_connectivity_request.is_empty(),
            "the held container must be consumed"
        );
        // The replayed container reached the ESM entity, which created the
        // session it names.
        let sess_id = ctx
            .sess_find_by_pti(mme_ue_id, 5)
            .expect("the ESM handler must have created the session");
        let sess = ctx.sess_find_by_id(sess_id).unwrap();
        assert_eq!(sess.ue_request_type, 1);
        assert_eq!(sess.ue_request_pdn_type, PdnType::Ipv4);
        assert_eq!(sess.apn, TEST_APN);
        assert_eq!(mme_ue.sess_list, vec![sess_id]);
    }

    #[test]
    fn test_standalone_pdn_connectivity_request_asks_for_esm_information() {
        let ctx = test_ctx();
        let enb_ue_id = enb_with_connection(&ctx);
        let mme_ue_id = ctx.mme_ue_add(enb_ue_id);
        ctx.enb_ue_associate_mme_ue(enb_ue_id, mme_ue_id);
        ctx.mme_ue_set_imsi(mme_ue_id, TEST_IMSI);
        {
            let mut pool = ctx.mme_ue_pool.write().unwrap();
            pool.get_mut(&mme_ue_id).unwrap().security_context_available = true;
        }

        // TS 24.301 §6.5.1.2: the transfer flag with no APN means the UE will
        // send them separately, so the MME asks.
        nas_eps_handle_uplink(&ctx, uplink(enb_ue_id, &pdn_connectivity_request(3, true)));

        let sess_id = ctx.sess_find_by_pti(mme_ue_id, 3).expect("session created");
        let bearer_id = ctx.sess_find_by_id(sess_id).unwrap().bearer_list[0];
        let bearer = ctx.bearer_find_by_id(bearer_id).unwrap();
        assert!(
            bearer.t3489.pkbuf.is_some(),
            "an ESM Information Request must be armed on T3489"
        );
    }

    #[test]
    fn test_esm_message_without_a_security_context_is_rejected() {
        let ctx = test_ctx();
        let enb_ue_id = enb_with_connection(&ctx);
        let mme_ue_id = ctx.mme_ue_add(enb_ue_id);
        ctx.enb_ue_associate_mme_ue(enb_ue_id, mme_ue_id);

        nas_eps_handle_uplink(&ctx, uplink(enb_ue_id, &pdn_connectivity_request(7, false)));

        // The ESM handler refused it (no security context), so the contexts the
        // request allocated are handed back rather than accumulating.
        assert!(ctx.sess_find_by_pti(mme_ue_id, 7).is_none());
        assert!(ctx.sess_pool.read().unwrap().is_empty());
        assert!(ctx.bearer_pool.read().unwrap().is_empty());
        assert!(ctx
            .mme_ue_find_by_id(mme_ue_id)
            .unwrap()
            .sess_list
            .is_empty());
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
