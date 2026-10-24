//! NAS Path Functions
//!
//! Port of src/mme/nas-path.c - NAS message sending functions
//!
//! Implements NAS message transmission to eNB and UE.

use crate::context::{EnbUe, MmeBearer, MmeContext, MmeSess, MmeUe, S1apCauseGroup};
use crate::emm_build::{self, EmmCause, SecurityHeaderType};
use crate::esm_build::{self, EsmCause};
use crate::nas_dispatch;
use crate::nas_security;
use crate::nas_timer;
use crate::s1ap_build;
use crate::s1ap_path;

// ============================================================================
// Result Types
// ============================================================================

/// NAS path operation result
pub type NasResult<T> = Result<T, NasError>;

/// NAS path error types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NasError {
    /// UE context not found
    UeNotFound,
    /// eNB UE context not found
    EnbUeNotFound,
    /// Session not found
    SessionNotFound,
    /// Bearer not found
    BearerNotFound,
    /// Message build failed
    BuildFailed,
    /// Send failed
    SendFailed,
    /// Invalid parameter
    InvalidParameter,
}

impl std::fmt::Display for NasError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NasError::UeNotFound => write!(f, "UE context not found"),
            NasError::EnbUeNotFound => write!(f, "eNB UE context not found"),
            NasError::SessionNotFound => write!(f, "Session not found"),
            NasError::BearerNotFound => write!(f, "Bearer not found"),
            NasError::BuildFailed => write!(f, "Message build failed"),
            NasError::SendFailed => write!(f, "Send failed"),
            NasError::InvalidParameter => write!(f, "Invalid parameter"),
        }
    }
}

impl std::error::Error for NasError {}

// ============================================================================
// GTP Create Action
// ============================================================================

/// GTP create action type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum GtpCreateAction {
    #[default]
    /// Create in attach request
    InAttachRequest,
    /// Create in tracking area update
    InTau,
    /// Create in PDN connectivity request
    InPdnConnectivity,
    /// Create in handover
    InHandover,
}

// ============================================================================
// S1AP Cause Types (simplified)
// ============================================================================

/// S1AP Cause for NAS
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S1apCauseNas {
    /// Normal release
    NormalRelease,
    /// Detach
    Detach,
    /// Authentication failure
    AuthenticationFailure,
    /// Unspecified
    Unspecified,
}

// ============================================================================
// Send to eNB Functions
// ============================================================================

/// Send NAS message to eNB
///
/// # Arguments
/// * `mme_ue` - MME UE context
/// * `enb_ue` - eNB UE context
/// * `message` - NAS message to send
///
/// # Returns
/// * `Ok(())` - Message sent successfully
/// * `Err(NasError)` - On error
pub fn nas_eps_send_to_enb(_mme_ue: &MmeUe, enb_ue: &EnbUe, s1ap_pdu: Vec<u8>) -> NasResult<()> {
    if enb_ue.id == 0 {
        log::error!("S1 context has already been removed");
        return Err(NasError::EnbUeNotFound);
    }

    log::debug!(
        "Sending S1AP PDU to eNB UE (mme_ue_s1ap_id={}, enb_ue_s1ap_id={}, enb_id={}), len={}",
        enb_ue.mme_ue_s1ap_id,
        enb_ue.enb_ue_s1ap_id,
        enb_ue.enb_id,
        s1ap_pdu.len()
    );

    // Queue for transmission on the eNB's S1 association (issue #42). This
    // previously only logged and returned Ok, so every downlink PDU the MME
    // built was silently discarded while the caller saw success.
    //
    // A failed queue push is NOT an error for the caller: it means no live S1
    // association to that eNB, which is indistinguishable from an eNB that has
    // gone away mid-procedure. It is logged by `s1ap_send_pdu`, and the EPS
    // procedure continues (its own timer will govern the retry), exactly as it
    // would for a lost message on the radio side.
    s1ap_path::s1ap_send_pdu(enb_ue.enb_id, s1ap_pdu);

    Ok(())
}

/// Send NAS message via downlink NAS transport
///
/// # Arguments
/// * `enb_ue` - eNB UE context
/// * `message` - NAS message to send
///
/// # Returns
/// * `Ok(())` - Message sent successfully
/// * `Err(NasError)` - On error
pub fn nas_eps_send_to_downlink_nas_transport(enb_ue: &EnbUe, message: Vec<u8>) -> NasResult<()> {
    if enb_ue.id == 0 {
        log::error!("S1 context has already been removed");
        return Err(NasError::EnbUeNotFound);
    }

    // Build S1AP downlink NAS transport message (APER via nextgcore-s1ap)
    let s1ap_message = s1ap_build::build_downlink_nas_transport(enb_ue, &message)
        .map_err(|_| NasError::BuildFailed)?;

    log::debug!(
        "Sending downlink NAS transport (mme_ue_s1ap_id={}, enb_ue_s1ap_id={}, enb_id={}), \
         nas_len={}, s1ap_len={}",
        enb_ue.mme_ue_s1ap_id,
        enb_ue.enb_ue_s1ap_id,
        enb_ue.enb_id,
        message.len(),
        s1ap_message.len()
    );

    // Transmit the built PDU instead of dropping it (issue #42).
    s1ap_path::s1ap_send_pdu(enb_ue.enb_id, s1ap_message);

    Ok(())
}

/// Forward the ESM message container carried by an EMM message to the ESM
/// entity (TS 24.301 §5.5.1.2.2).
///
/// # Arguments
/// * `ctx` - MME context (the ESM entity owns sessions and bearers)
/// * `enb_ue` - eNB UE context the message arrived on
/// * `mme_ue` - MME UE context
/// * `esm_message_container` - ESM message container from the EMM message
///
/// # Returns
/// * `Ok(())` - Message forwarded to the ESM handler
/// * `Err(NasError)` - On error
///
/// Must not be called while the `mme_ue_pool` lock is held: the ESM dispatch
/// looks up session and bearer contexts, and `std::sync::RwLock` is not
/// reentrant. Take a snapshot of `mme_ue` and drop the guard first.
pub fn nas_eps_send_emm_to_esm(
    ctx: &MmeContext,
    enb_ue: &EnbUe,
    mme_ue: &MmeUe,
    esm_message_container: &[u8],
) -> NasResult<()> {
    if mme_ue.id == 0 {
        log::error!("UE(mme-ue) context has already been removed");
        return Err(NasError::UeNotFound);
    }

    if esm_message_container.is_empty() {
        log::error!("Invalid ESM Message Container");
        return Err(NasError::InvalidParameter);
    }

    log::debug!(
        "Forwarding EMM to ESM for UE (imsi={}), len={}",
        mme_ue.imsi_bcd,
        esm_message_container.len()
    );

    // Deliver it (issue #43). This previously logged and returned Ok, so the
    // piggybacked ESM message — the PDN Connectivity Request that carries the
    // APN of the default bearer — never reached `esm_handler`.
    nas_dispatch::handle_esm_message(ctx, enb_ue, mme_ue, esm_message_container);

    Ok(())
}

// ============================================================================
// EMM Message Send Functions
// ============================================================================
/// The T3412 value to signal, in seconds (TS 23.401 §4.3.17.3, TS 29.272 §7.3.134).
///
/// The subscription wins, then the configured default. Both accepts wrote a literal
/// 3600 before #46 while the S6a codec had been round-tripping the subscribed timer
/// all along — so every UE was told to re-register on a cadence its own subscription
/// had not asked for.
///
/// `mme.time.t3412` is the configured fallback and is already parsed; a deployment
/// that sets neither gets the shipped 3600, which is the value that used to be
/// hardcoded, so nothing changes for a subscription that states no timer.
fn t3412_for(mme_ue: &MmeUe) -> u32 {
    t3412_from(
        mme_ue.subscribed_rau_tau_timer,
        crate::context::mme_self().time.t3412,
    )
}

/// The precedence, as a pure function of the two inputs.
///
/// Split from [`t3412_for`] so the ordering is testable without the process-global
/// context: `mme_self().time` is a plain field set at construction, so a test cannot
/// vary the configured value, and the precedence is the part worth pinning.
fn t3412_from(subscribed: u32, configured: u64) -> u32 {
    /// What used to be hardcoded, so a deployment that configures nothing and a
    /// subscription that states nothing behave exactly as before.
    const DEFAULT_T3412_SECS: u32 = 3600;

    if subscribed > 0 {
        return subscribed;
    }
    if configured > 0 {
        return configured as u32;
    }
    DEFAULT_T3412_SECS
}

/// Send attach accept message
///
/// # Arguments
/// * `mme_ue` - MME UE context
/// * `enb_ue` - eNB UE context
/// * `sess` - Session context
/// * `default_bearer` - Default EPS bearer for the Initial Context Setup E-RAB
///
/// # Returns
/// * `Ok(())` - Message sent successfully
/// * `Err(NasError)` - On error
pub fn nas_eps_send_attach_accept(
    mme_ue: &mut MmeUe,
    enb_ue: &EnbUe,
    sess: &MmeSess,
    default_bearer: &MmeBearer,
    ue_ambr: nextgcore_s1ap::UeAmbr,
) -> NasResult<()> {
    if mme_ue.id == 0 {
        log::error!("UE(mme-ue) context has already been removed");
        return Err(NasError::UeNotFound);
    }

    if enb_ue.id == 0 {
        log::error!("S1 context has already been removed");
        return Err(NasError::EnbUeNotFound);
    }

    log::debug!("[{}] Attach accept", mme_ue.imsi_bcd);

    // Build ESM activate default bearer context request.
    //
    // #329: `_with_params` and the REAL `default_bearer`, not the simplified helper.
    // That helper fabricates `ebi: 5` because it has no bearer to name, and this
    // function is handed the actual default bearer — so the simplified call made the
    // Attach Accept tell the UE to bind EBI 5 whatever the MME had actually created,
    // and the E-RAB in the enclosing Initial Context Setup (built from
    // `default_bearer` a few lines below) could then name a different one.
    let esm_message = esm_build::build_activate_default_bearer_context_request_with_params(
        sess,
        default_bearer,
        esm_build::CreateAction::InAttachRequest,
    );

    // Build EMM attach accept with ESM message
    let tai_list = vec![mme_ue.tai.clone()];
    let emm_message =
        emm_build::build_attach_accept(mme_ue, &esm_message, t3412_for(mme_ue), &tai_list)
            .map_err(|_| NasError::BuildFailed)?;

    // Apply security encoding
    let secured_message = nas_security::nas_eps_security_encode(
        mme_ue,
        SecurityHeaderType::IntegrityProtectedAndCiphered,
        &emm_message,
    )
    .ok_or(NasError::BuildFailed)?;

    // Build S1AP initial context setup request (APER via nextgcore-s1ap). The
    // Attach Accept NAS message travels inside this PDU, so the PDU — not the
    // bare NAS message — is what goes to the eNB (issue #42).
    let s1ap_message = s1ap_build::build_initial_context_setup_request(
        mme_ue,
        enb_ue,
        std::slice::from_ref(default_bearer),
        Some(&secured_message),
        ue_ambr,
    )
    .map_err(|e| {
        log::error!(
            "[{}] Initial Context Setup Request build failed: {e:?}",
            mme_ue.imsi_bcd
        );
        NasError::BuildFailed
    })?;
    mme_ue.ics_pending_on = enb_ue.id;

    // Store for retransmission and arm T3450 (issue #45) only now that the Initial
    // Context Setup carrying the accept exists (#495). Arming it first left a bare
    // ATTACH ACCEPT to be retransmitted over Downlink NAS Transport -- no E-RAB, no
    // AS security -- whenever the build failed.
    mme_ue.t3450.pkbuf = Some(secured_message);
    mme_ue.t3450.start(nas_timer::T3450_DURATION);

    // Clear UE radio capability as per TS24.301
    mme_ue.ue_radio_capability.clear();

    nas_eps_send_to_enb(mme_ue, enb_ue, s1ap_message)
}

/// Send attach reject message, then release the UE's S1 connection
///
/// # Arguments
/// * `ctx` - MME context (the release marks the eNB UE context)
/// * `enb_ue` - eNB UE context
/// * `mme_ue` - MME UE context
/// * `emm_cause` - EMM cause code
/// * `esm_cause` - ESM cause code (optional)
///
/// # Returns
/// * `Ok(())` - Message sent successfully
/// * `Err(NasError)` - On error
pub fn nas_eps_send_attach_reject(
    ctx: &MmeContext,
    enb_ue: &EnbUe,
    mme_ue: &MmeUe,
    emm_cause: EmmCause,
    esm_cause: Option<EsmCause>,
) -> NasResult<()> {
    if mme_ue.id == 0 {
        log::error!("UE(mme-ue) context has already been removed");
        return Err(NasError::UeNotFound);
    }

    if enb_ue.id == 0 {
        log::error!("S1 context has already been removed");
        return Err(NasError::EnbUeNotFound);
    }

    log::debug!(
        "[{}] Attach reject, Cause[{:?}]",
        mme_ue.imsi_bcd,
        emm_cause
    );

    // Build ESM PDN connectivity reject if ESM cause provided
    let esm_message = esm_cause.map(esm_build::build_pdn_connectivity_reject);

    // Build EMM attach reject
    let emm_message = emm_build::build_attach_reject(emm_cause, esm_message.as_deref());

    let sent = nas_eps_send_to_downlink_nas_transport(enb_ue, emm_message);

    // TS 24.301 §5.3.1.2.1: releasing the NAS signalling connection is the
    // network's job, and a rejected UE does not release it itself. For the causes
    // of §5.3.1.2.1 a) (#11-#15, #25, #31, #35, #42, #78) the UE starts T3440 for
    // the explicit purpose of letting the network release it; for the rest
    // (e.g. #17, abnormal case d of §5.5.1.2.6) it starts T3411 and retries, and a
    // release after the reject is not an abnormal case for it (case b only covers
    // a release BEFORE the reject arrives). So the MME releases after every
    // Attach Reject (TS 23.401 §5.3.5 MME-initiated S1 release, TS 36.413 §8.3.3),
    // as the AMF does after a Registration Reject (`reject_and_release`, #359) --
    // otherwise the UE stays RRC-connected and the eNB UE context is held for a
    // deregistered UE until the RAN gives up on it.
    //
    // Ordering: both PDUs go through the one S1AP send queue, so the Downlink NAS
    // Transport carrying the reject is on the wire before the release command.
    // The release runs whether or not the reject was queued, because the release
    // is the part that must happen (the same reasoning as #359).
    nas_dispatch::release_ue_context_with_cause(ctx, enb_ue, s1ap_build::nas_cause::NORMAL_RELEASE);

    sent
}

/// Send identity request message
///
/// # Arguments
/// * `mme_ue` - MME UE context
/// * `enb_ue` - eNB UE context
///
/// # Returns
/// * `Ok(())` - Message sent successfully
/// * `Err(NasError)` - On error
pub fn nas_eps_send_identity_request(mme_ue: &mut MmeUe, enb_ue: &EnbUe) -> NasResult<()> {
    if mme_ue.id == 0 {
        log::error!("UE(mme-ue) context has already been removed");
        return Err(NasError::UeNotFound);
    }

    if enb_ue.id == 0 {
        log::error!("S1 context has already been removed");
        return Err(NasError::EnbUeNotFound);
    }

    log::debug!("Identity request");

    // Use stored message if available (retransmission)
    let emm_message = if let Some(ref pkbuf) = mme_ue.t3470.pkbuf {
        pkbuf.clone()
    } else {
        emm_build::build_identity_request(emm_build::IdentityType2::Imsi)
    };

    // Store for retransmission and arm T3470 (issue #45).
    mme_ue.t3470.pkbuf = Some(emm_message.clone());
    mme_ue.t3470.start(nas_timer::T3470_DURATION);

    nas_eps_send_to_downlink_nas_transport(enb_ue, emm_message)
}

/// Send authentication request message
///
/// # Arguments
/// * `mme_ue` - MME UE context
/// * `enb_ue` - eNB UE context
///
/// # Returns
/// * `Ok(())` - Message sent successfully
/// * `Err(NasError)` - On error
pub fn nas_eps_send_authentication_request(mme_ue: &mut MmeUe, enb_ue: &EnbUe) -> NasResult<()> {
    if mme_ue.id == 0 {
        log::error!("UE(mme-ue) context has already been removed");
        return Err(NasError::UeNotFound);
    }

    if enb_ue.id == 0 {
        log::error!("S1 context has already been removed");
        return Err(NasError::EnbUeNotFound);
    }

    log::debug!("[{}] Authentication request", mme_ue.imsi_bcd);

    // Use stored message if available (retransmission)
    let emm_message = if let Some(ref pkbuf) = mme_ue.t3460.pkbuf {
        pkbuf.clone()
    } else {
        let ksi = mme_ue.nas_eps.mme_ksi.ksi;
        emm_build::build_authentication_request(ksi, &mme_ue.rand, &mme_ue.autn)
    };

    // Store for retransmission and arm T3460 (issue #45).
    mme_ue.t3460.pkbuf = Some(emm_message.clone());
    mme_ue.t3460.start(nas_timer::T3460_DURATION);

    nas_eps_send_to_downlink_nas_transport(enb_ue, emm_message)
}

/// Send authentication reject message
///
/// # Arguments
/// * `mme_ue` - MME UE context
/// * `enb_ue` - eNB UE context
///
/// # Returns
/// * `Ok(())` - Message sent successfully
/// * `Err(NasError)` - On error
pub fn nas_eps_send_authentication_reject(mme_ue: &MmeUe, enb_ue: &EnbUe) -> NasResult<()> {
    if mme_ue.id == 0 {
        log::error!("UE(mme-ue) context has already been removed");
        return Err(NasError::UeNotFound);
    }

    if enb_ue.id == 0 {
        log::error!("S1 context has already been removed");
        return Err(NasError::EnbUeNotFound);
    }

    log::debug!("[{}] Authentication reject", mme_ue.imsi_bcd);

    let emm_message = emm_build::build_authentication_reject();

    nas_eps_send_to_downlink_nas_transport(enb_ue, emm_message)
}

/// Send security mode command message
///
/// # Arguments
/// * `mme_ue` - MME UE context
/// * `enb_ue` - eNB UE context
///
/// # Returns
/// * `Ok(())` - Message sent successfully
/// * `Err(NasError)` - On error
pub fn nas_eps_send_security_mode_command(mme_ue: &mut MmeUe, enb_ue: &EnbUe) -> NasResult<()> {
    if mme_ue.id == 0 {
        log::error!("UE(mme-ue) context has already been removed");
        return Err(NasError::UeNotFound);
    }

    if enb_ue.id == 0 {
        log::error!("S1 context has already been removed");
        return Err(NasError::EnbUeNotFound);
    }

    log::debug!("[{}] Security mode command", mme_ue.imsi_bcd);

    // Use stored message if available (retransmission)
    let emm_message = if let Some(ref pkbuf) = mme_ue.t3460.pkbuf {
        pkbuf.clone()
    } else {
        let ksi = mme_ue.nas_eps.mme_ksi.ksi;
        let plain_message = emm_build::build_security_mode_command(
            mme_ue,
            ksi,
            mme_ue.selected_enc_algorithm,
            mme_ue.selected_int_algorithm,
        );

        // Apply security encoding with new security context
        nas_security::nas_eps_security_encode(
            mme_ue,
            SecurityHeaderType::IntegrityProtectedNewContext,
            &plain_message,
        )
        .ok_or(NasError::BuildFailed)?
    };

    // Store for retransmission and arm T3460 (issue #45).
    mme_ue.t3460.pkbuf = Some(emm_message.clone());
    mme_ue.t3460.start(nas_timer::T3460_DURATION);

    nas_eps_send_to_downlink_nas_transport(enb_ue, emm_message)
}

/// Send detach request message (to UE)
///
/// # Arguments
/// * `mme_ue` - MME UE context
/// * `enb_ue` - eNB UE context
/// * `detach_type` - TS 24.301 §9.9.3.7 detach type to the UE
///
/// # Returns
/// * `Ok(())` - Message sent successfully
/// * `Err(NasError)` - On error
pub fn nas_eps_send_detach_request(
    mme_ue: &mut MmeUe,
    enb_ue: &EnbUe,
    detach_type: emm_build::DetachTypeToUe,
) -> NasResult<()> {
    if mme_ue.id == 0 {
        log::error!("UE(mme-ue) context has already been removed");
        return Err(NasError::UeNotFound);
    }

    if enb_ue.id == 0 {
        log::error!("S1 context has already been removed");
        return Err(NasError::EnbUeNotFound);
    }

    log::debug!("[{}] Detach request to UE", mme_ue.imsi_bcd);

    // Use stored message if available (retransmission)
    let emm_message = if let Some(ref pkbuf) = mme_ue.t3422.pkbuf {
        pkbuf.clone()
    } else {
        let plain_message = emm_build::build_detach_request(mme_ue, detach_type);

        // Apply security encoding
        nas_security::nas_eps_security_encode(
            mme_ue,
            SecurityHeaderType::IntegrityProtectedAndCiphered,
            &plain_message,
        )
        .ok_or(NasError::BuildFailed)?
    };

    // Store for retransmission (T3422)
    mme_ue.t3422.pkbuf = Some(emm_message.clone());

    nas_eps_send_to_downlink_nas_transport(enb_ue, emm_message)
}

/// Send detach accept message
///
/// # Arguments
/// * `mme_ue` - MME UE context
/// * `enb_ue` - eNB UE context
///
/// # Returns
/// * `Ok(())` - Message sent successfully
/// * `Err(NasError)` - On error
pub fn nas_eps_send_detach_accept(mme_ue: &mut MmeUe, enb_ue: &EnbUe) -> NasResult<()> {
    if mme_ue.id == 0 {
        log::error!("UE(mme-ue) context has already been removed");
        return Err(NasError::UeNotFound);
    }

    if enb_ue.id == 0 {
        log::error!("S1 context has already been removed");
        return Err(NasError::EnbUeNotFound);
    }

    log::debug!("[{}] Detach accept", mme_ue.imsi_bcd);

    // Only send detach accept if not switch-off
    // (nas_eps.detach.switch_off check would be here)
    let plain_message = emm_build::build_detach_accept(mme_ue);

    // Apply security encoding
    let emm_message = nas_security::nas_eps_security_encode(
        mme_ue,
        SecurityHeaderType::IntegrityProtectedAndCiphered,
        &plain_message,
    )
    .ok_or(NasError::BuildFailed)?;

    nas_eps_send_to_downlink_nas_transport(enb_ue, emm_message)
}

/// Send TAU accept message
///
/// # Arguments
/// * `mme_ue` - MME UE context
/// * `enb_ue` - eNB UE context
/// * `use_initial_context_setup` - Whether to use initial context setup
/// * `bearers` - Active EPS bearers for the Initial Context Setup E-RAB list
///
/// # Returns
/// * `Ok(())` - Message sent successfully
/// * `Err(NasError)` - On error
pub fn nas_eps_send_tau_accept(
    mme_ue: &mut MmeUe,
    enb_ue: &EnbUe,
    use_initial_context_setup: bool,
    bearers: &[MmeBearer],
    ue_ambr: nextgcore_s1ap::UeAmbr,
) -> NasResult<()> {
    if mme_ue.id == 0 {
        log::error!("UE(mme-ue) context has already been removed");
        return Err(NasError::UeNotFound);
    }

    if enb_ue.id == 0 {
        log::error!("S1 context has already been removed");
        return Err(NasError::EnbUeNotFound);
    }

    log::debug!("[{}] Tracking area update accept", mme_ue.imsi_bcd);

    let tai_list = vec![mme_ue.tai.clone()];
    // The EPS bearer context status is built from the bearers the caller passed, so
    // the UE and the MME can discover a disagreement about which bearers exist —
    // which is the IE's only purpose, and it was always sent as 0.
    let bearer_status = emm_build::eps_bearer_context_status(bearers.iter().map(|b| b.ebi));
    let plain_message =
        emm_build::build_tau_accept(mme_ue, t3412_for(mme_ue), &tai_list, bearer_status);

    // Apply security encoding
    let emm_message = nas_security::nas_eps_security_encode(
        mme_ue,
        SecurityHeaderType::IntegrityProtectedAndCiphered,
        &plain_message,
    )
    .ok_or(NasError::BuildFailed)?;

    // Store for retransmission and arm T3450 (issue #45).
    mme_ue.t3450.pkbuf = Some(emm_message.clone());
    mme_ue.t3450.start(nas_timer::T3450_DURATION);

    if use_initial_context_setup {
        // The TAU Accept travels inside the Initial Context Setup Request, so
        // transmit that PDU rather than the bare NAS message (issue #42).
        let s1ap_message = s1ap_build::build_initial_context_setup_request(
            mme_ue,
            enb_ue,
            bearers,
            Some(&emm_message),
            ue_ambr,
        )
        .map_err(|_| NasError::BuildFailed)?;
        mme_ue.ics_pending_on = enb_ue.id;
        nas_eps_send_to_enb(mme_ue, enb_ue, s1ap_message)
    } else {
        nas_eps_send_to_downlink_nas_transport(enb_ue, emm_message)
    }
}

/// Send TAU reject message
///
/// # Arguments
/// * `enb_ue` - eNB UE context
/// * `mme_ue` - MME UE context
/// * `emm_cause` - EMM cause code
///
/// # Returns
/// * `Ok(())` - Message sent successfully
/// * `Err(NasError)` - On error
pub fn nas_eps_send_tau_reject(
    enb_ue: &EnbUe,
    mme_ue: &MmeUe,
    emm_cause: EmmCause,
) -> NasResult<()> {
    if mme_ue.id == 0 {
        log::error!("UE(mme-ue) context has already been removed");
        return Err(NasError::UeNotFound);
    }

    if enb_ue.id == 0 {
        log::error!("S1 context has already been removed");
        return Err(NasError::EnbUeNotFound);
    }

    log::debug!("[{}] Tracking area update reject", mme_ue.imsi_bcd);

    let emm_message = emm_build::build_tau_reject(emm_cause);

    nas_eps_send_to_downlink_nas_transport(enb_ue, emm_message)
}

/// Send service reject message
///
/// # Arguments
/// * `enb_ue` - eNB UE context
/// * `mme_ue` - MME UE context
/// * `emm_cause` - EMM cause code
///
/// # Returns
/// * `Ok(())` - Message sent successfully
/// * `Err(NasError)` - On error
pub fn nas_eps_send_service_reject(
    enb_ue: &EnbUe,
    mme_ue: &MmeUe,
    emm_cause: EmmCause,
) -> NasResult<()> {
    if mme_ue.id == 0 {
        log::error!("UE(mme-ue) context has already been removed");
        return Err(NasError::UeNotFound);
    }

    if enb_ue.id == 0 {
        log::error!("S1 context has already been removed");
        return Err(NasError::EnbUeNotFound);
    }

    log::debug!("[{}] Service reject", mme_ue.imsi_bcd);

    let emm_message = emm_build::build_service_reject(emm_cause);

    nas_eps_send_to_downlink_nas_transport(enb_ue, emm_message)
}

/// Send CS service notification message
///
/// # Arguments
/// * `mme_ue` - MME UE context
/// * `enb_ue` - eNB UE context
///
/// # Returns
/// * `Ok(())` - Message sent successfully
/// * `Err(NasError)` - On error
pub fn nas_eps_send_cs_service_notification(mme_ue: &mut MmeUe, enb_ue: &EnbUe) -> NasResult<()> {
    if mme_ue.id == 0 {
        log::error!("UE(mme-ue) context has already been removed");
        return Err(NasError::UeNotFound);
    }

    if enb_ue.id == 0 {
        log::error!("S1 context has already been removed");
        return Err(NasError::EnbUeNotFound);
    }

    log::debug!("[{}] CS Service Notification", mme_ue.imsi_bcd);

    let plain_message = emm_build::build_cs_service_notification(1); // Paging identity

    // Apply security encoding
    let emm_message = nas_security::nas_eps_security_encode(
        mme_ue,
        SecurityHeaderType::IntegrityProtectedAndCiphered,
        &plain_message,
    )
    .ok_or(NasError::BuildFailed)?;

    nas_eps_send_to_downlink_nas_transport(enb_ue, emm_message)
}

// ============================================================================
// ESM Message Send Functions
// ============================================================================

/// Send PDN connectivity reject message
///
/// # Arguments
/// * `sess` - Session context
/// * `mme_ue` - MME UE context
/// * `enb_ue` - eNB UE context
/// * `esm_cause` - ESM cause code
/// * `create_action` - GTP create action
///
/// # Returns
/// * `Ok(())` - Message sent successfully
/// * `Err(NasError)` - On error
pub fn nas_eps_send_pdn_connectivity_reject(
    ctx: &MmeContext,
    _sess: &MmeSess,
    mme_ue: &MmeUe,
    enb_ue: &EnbUe,
    esm_cause: EsmCause,
    create_action: GtpCreateAction,
) -> NasResult<()> {
    if mme_ue.id == 0 {
        log::error!("UE(mme-ue) context has already been removed");
        return Err(NasError::UeNotFound);
    }

    if enb_ue.id == 0 {
        log::error!("S1 context has already been removed");
        return Err(NasError::EnbUeNotFound);
    }

    if create_action == GtpCreateAction::InAttachRequest {
        // During attach, send attach reject with piggybacked PDN connectivity reject
        return nas_eps_send_attach_reject(
            ctx,
            enb_ue,
            mme_ue,
            EmmCause::EsmFailure,
            Some(esm_cause),
        );
    }

    let esm_message = protect_esm(
        ctx,
        mme_ue.id,
        &esm_build::build_pdn_connectivity_reject(esm_cause),
    )?;

    nas_eps_send_to_downlink_nas_transport(enb_ue, esm_message)
}

/// Integrity-protect and cipher a downlink ESM message under the UE's LIVE EPS
/// security context (#497).
///
/// The ESM builders produce the plain message; until #497 they wrote a
/// placeholder "integrity protected and ciphered" header with MAC 0 and sequence
/// number 0 over a plaintext body, which a UE in an established security context
/// must discard (TS 24.301 §4.4.4.2). The ESM handlers work on a snapshot of the
/// UE (`mme_ue_find_by_id` clones), so the protection is applied to the pool's
/// context: that is what advances the downlink NAS COUNT (§4.4.3.1), so the next
/// message cannot reuse it. The caller must not hold an `mme_ue_pool` guard.
pub fn protect_esm(ctx: &MmeContext, mme_ue_id: u64, plain: &[u8]) -> NasResult<Vec<u8>> {
    let mut pool = ctx.mme_ue_pool.write().map_err(|_| NasError::UeNotFound)?;
    let mme_ue = pool.get_mut(&mme_ue_id).ok_or(NasError::UeNotFound)?;
    nas_security::nas_eps_security_encode(
        mme_ue,
        SecurityHeaderType::IntegrityProtectedAndCiphered,
        plain,
    )
    .ok_or(NasError::BuildFailed)
}

/// Send ESM information request message
///
/// # Arguments
/// * `bearer` - Bearer context
/// * `mme_ue` - MME UE context
/// * `enb_ue` - eNB UE context
///
/// # Returns
/// * `Ok(())` - Message sent successfully
/// * `Err(NasError)` - On error
pub fn nas_eps_send_esm_information_request(
    ctx: &MmeContext,
    bearer_id: u64,
    mme_ue: &MmeUe,
    enb_ue: &EnbUe,
) -> NasResult<()> {
    if mme_ue.id == 0 {
        log::error!("UE(mme-ue) context has already been removed");
        return Err(NasError::UeNotFound);
    }

    if enb_ue.id == 0 {
        log::error!("S1 context has already been removed");
        return Err(NasError::EnbUeNotFound);
    }

    // T3489 keeps the PLAIN message (#497): each (re)transmission is protected
    // afresh, under the next downlink NAS COUNT, rather than replaying one. The
    // bearer guard is released before `protect_esm` takes the UE pool's, so the
    // two locks are never nested.
    let plain = {
        let mut pool = ctx
            .bearer_pool
            .write()
            .map_err(|_| NasError::InvalidParameter)?;
        let bearer = pool.get_mut(&bearer_id).ok_or(NasError::InvalidParameter)?;
        bearer
            .t3489
            .pkbuf
            .get_or_insert_with(|| esm_build::build_esm_information_request(0))
            .clone()
    };

    nas_eps_send_to_downlink_nas_transport(enb_ue, protect_esm(ctx, mme_ue.id, &plain)?)
}

/// Send activate default bearer context request message
///
/// # Arguments
/// * `bearer` - Bearer context
/// * `sess` - Session context
/// * `mme_ue` - MME UE context
/// * `enb_ue` - eNB UE context
/// * `create_action` - GTP create action
///
/// # Returns
/// * `Ok(())` - Message sent successfully
/// * `Err(NasError)` - On error
pub fn nas_eps_send_activate_default_bearer_context_request(
    ctx: &MmeContext,
    bearer: &MmeBearer,
    sess: &MmeSess,
    mme_ue: &MmeUe,
    enb_ue: &EnbUe,
    create_action: GtpCreateAction,
) -> NasResult<()> {
    if mme_ue.id == 0 {
        log::error!("UE(mme-ue) context has already been removed");
        return Err(NasError::UeNotFound);
    }

    if enb_ue.id == 0 {
        log::error!("S1 context has already been removed");
        return Err(NasError::EnbUeNotFound);
    }

    let esm_message = protect_esm(
        ctx,
        mme_ue.id,
        &esm_build::build_activate_default_bearer_context_request(sess, create_action),
    )?;

    // Build S1AP E-RAB setup request (APER via nextgcore-s1ap). The ESM message
    // is carried inside it, so transmit the PDU (issue #42).
    // A new PDN connection changes the UE-AMBR (TS 23.401 §5.10.2 step 9, #811).
    let s1ap_message = s1ap_build::build_e_rab_setup_request(
        enb_ue,
        bearer,
        &esm_message,
        Some(s1ap_build::ue_ambr_of(ctx, mme_ue)),
    )
    .map_err(|_| NasError::BuildFailed)?;

    nas_eps_send_to_enb(mme_ue, enb_ue, s1ap_message)
}

/// Send activate dedicated bearer context request message
///
/// # Arguments
/// * `bearer` - Bearer context
/// * `mme_ue` - MME UE context
/// * `enb_ue` - eNB UE context
///
/// # Returns
/// * `Ok(())` - Message sent successfully
/// * `Err(NasError)` - On error
pub fn nas_eps_send_activate_dedicated_bearer_context_request(
    ctx: &MmeContext,
    bearer: &MmeBearer,
    mme_ue: &MmeUe,
    enb_ue: &EnbUe,
) -> NasResult<()> {
    if mme_ue.id == 0 {
        log::error!("UE(mme-ue) context has already been removed");
        return Err(NasError::UeNotFound);
    }

    if enb_ue.id == 0 {
        log::error!("S1 context has already been removed");
        return Err(NasError::EnbUeNotFound);
    }

    let esm_message = protect_esm(
        ctx,
        mme_ue.id,
        &esm_build::build_activate_dedicated_bearer_context_request(bearer),
    )?;

    // Build S1AP E-RAB setup request (APER via nextgcore-s1ap). The ESM message
    // is carried inside it, so transmit the PDU (issue #42).
    let s1ap_message = s1ap_build::build_e_rab_setup_request(enb_ue, bearer, &esm_message, None)
        .map_err(|_| NasError::BuildFailed)?;

    nas_eps_send_to_enb(mme_ue, enb_ue, s1ap_message)
}

/// Send modify bearer context request message
///
/// # Arguments
/// * `bearer` - Bearer context
/// * `mme_ue` - MME UE context
/// * `enb_ue` - eNB UE context
/// * `qos_presence` - Whether QoS is present
/// * `tft_presence` - Whether TFT is present
///
/// # Returns
/// * `Ok(())` - Message sent successfully
/// * `Err(NasError)` - On error
pub fn nas_eps_send_modify_bearer_context_request(
    ctx: &MmeContext,
    bearer: &MmeBearer,
    mme_ue: &MmeUe,
    enb_ue: &EnbUe,
    qos_presence: bool,
    tft_presence: bool,
) -> NasResult<()> {
    if mme_ue.id == 0 {
        log::error!("UE(mme-ue) context has already been removed");
        return Err(NasError::UeNotFound);
    }

    if enb_ue.id == 0 {
        log::error!("S1 context has already been removed");
        return Err(NasError::EnbUeNotFound);
    }

    let esm_message = protect_esm(
        ctx,
        mme_ue.id,
        &esm_build::build_modify_bearer_context_request(bearer, qos_presence, tft_presence),
    )?;

    if qos_presence {
        // Build S1AP E-RAB modify request (APER via nextgcore-s1ap). The ESM
        // message is carried inside it, so transmit the PDU (issue #42).
        let s1ap_message = s1ap_build::build_e_rab_modify_request(enb_ue, bearer, &esm_message)
            .map_err(|_| NasError::BuildFailed)?;
        nas_eps_send_to_enb(mme_ue, enb_ue, s1ap_message)
    } else {
        nas_eps_send_to_downlink_nas_transport(enb_ue, esm_message)
    }
}

/// Send deactivate bearer context request message
///
/// # Arguments
/// * `bearer` - Bearer context
/// * `mme_ue` - MME UE context
/// * `enb_ue` - eNB UE context
///
/// # Returns
/// * `Ok(())` - Message sent successfully
/// * `Err(NasError)` - On error
pub fn nas_eps_send_deactivate_bearer_context_request(
    ctx: &MmeContext,
    bearer: &MmeBearer,
    mme_ue: &MmeUe,
    enb_ue: &EnbUe,
) -> NasResult<()> {
    if mme_ue.id == 0 {
        log::error!("UE(mme-ue) context has already been removed");
        return Err(NasError::UeNotFound);
    }

    if enb_ue.id == 0 {
        log::error!("S1 context has already been removed");
        return Err(NasError::EnbUeNotFound);
    }

    let esm_message = protect_esm(
        ctx,
        mme_ue.id,
        &esm_build::build_deactivate_bearer_context_request(bearer, EsmCause::RegularDeactivation),
    )?;

    // Build S1AP E-RAB release command (APER via nextgcore-s1ap). The ESM
    // message is carried inside it, so transmit the PDU (issue #42).
    let s1ap_message = s1ap_build::build_e_rab_release_command(
        enb_ue,
        bearer.ebi,
        S1apCauseGroup::Nas,
        s1ap_build::nas_cause::NORMAL_RELEASE,
        Some(&esm_message),
        None,
    )
    .map_err(|_| NasError::BuildFailed)?;

    nas_eps_send_to_enb(mme_ue, enb_ue, s1ap_message)
}

/// Send bearer resource allocation reject message
///
/// # Arguments
/// * `mme_ue` - MME UE context
/// * `enb_ue` - eNB UE context
/// * `pti` - Procedure transaction identity
/// * `esm_cause` - ESM cause code
///
/// # Returns
/// * `Ok(())` - Message sent successfully
/// * `Err(NasError)` - On error
pub fn nas_eps_send_bearer_resource_allocation_reject(
    ctx: &MmeContext,
    mme_ue: &MmeUe,
    enb_ue: &EnbUe,
    pti: u8,
    esm_cause: EsmCause,
) -> NasResult<()> {
    if mme_ue.id == 0 {
        log::error!("UE(mme-ue) context has already been removed");
        return Err(NasError::UeNotFound);
    }

    if enb_ue.id == 0 {
        log::error!("S1 context has already been removed");
        return Err(NasError::EnbUeNotFound);
    }

    if pti == 0 {
        log::error!("Invalid PTI");
        return Err(NasError::InvalidParameter);
    }

    let esm_message = protect_esm(
        ctx,
        mme_ue.id,
        &esm_build::build_bearer_resource_allocation_reject(pti, esm_cause),
    )?;

    nas_eps_send_to_downlink_nas_transport(enb_ue, esm_message)
}

/// Send bearer resource modification reject message
///
/// # Arguments
/// * `mme_ue` - MME UE context
/// * `enb_ue` - eNB UE context
/// * `pti` - Procedure transaction identity
/// * `esm_cause` - ESM cause code
///
/// # Returns
/// * `Ok(())` - Message sent successfully
/// * `Err(NasError)` - On error
pub fn nas_eps_send_bearer_resource_modification_reject(
    ctx: &MmeContext,
    mme_ue: &MmeUe,
    enb_ue: &EnbUe,
    pti: u8,
    esm_cause: EsmCause,
) -> NasResult<()> {
    if mme_ue.id == 0 {
        log::error!("UE(mme-ue) context has already been removed");
        return Err(NasError::UeNotFound);
    }

    if enb_ue.id == 0 {
        log::error!("S1 context has already been removed");
        return Err(NasError::EnbUeNotFound);
    }

    if pti == 0 {
        log::error!("Invalid PTI");
        return Err(NasError::InvalidParameter);
    }

    let esm_message = protect_esm(
        ctx,
        mme_ue.id,
        &esm_build::build_bearer_resource_modification_reject(pti, esm_cause),
    )?;

    nas_eps_send_to_downlink_nas_transport(enb_ue, esm_message)
}

/// Send downlink NAS transport message (generic)
///
/// # Arguments
/// * `mme_ue` - MME UE context
/// * `enb_ue` - eNB UE context
/// * `buffer` - NAS message buffer
///
/// # Returns
/// * `Ok(())` - Message sent successfully
/// * `Err(NasError)` - On error
pub fn nas_eps_send_downlink_nas_transport(
    mme_ue: &mut MmeUe,
    enb_ue: &EnbUe,
    buffer: &[u8],
) -> NasResult<()> {
    if mme_ue.id == 0 {
        log::error!("UE(mme-ue) context has already been removed");
        return Err(NasError::UeNotFound);
    }

    if enb_ue.id == 0 {
        log::error!("S1 context has already been removed");
        return Err(NasError::EnbUeNotFound);
    }

    if buffer.is_empty() {
        log::error!("Empty buffer");
        return Err(NasError::InvalidParameter);
    }

    log::debug!("[{}] Downlink NAS transport", mme_ue.imsi_bcd);

    // Build EMM downlink NAS transport message
    let emm_message = emm_build::build_emm_information(None, None, None, None, None);

    // Apply security encoding
    let secured_message = nas_security::nas_eps_security_encode(
        mme_ue,
        SecurityHeaderType::IntegrityProtectedAndCiphered,
        &emm_message,
    )
    .ok_or(NasError::BuildFailed)?;

    nas_eps_send_to_downlink_nas_transport(enb_ue, secured_message)
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// #869 review MINOR 1, TS 23.401 §5.10.2 step 9: the E-RAB SETUP REQUEST
    /// of a new PDN connection's default bearer carries the UE-AMBR of the
    /// active APNs, the new one included.
    #[test]
    fn the_new_pdn_e_rab_setup_carries_the_ue_ambr() {
        use nextgcore_s1ap_gen::generated as g;
        let _guard = crate::gtp_path::lock_s11();
        let ctx = MmeContext::new();
        ctx.init();
        let enb_id = ctx.enb_add("127.0.0.1:36869".parse().unwrap());
        let enb_ue_id = ctx.enb_ue_add(enb_id, 869);
        let mme_ue_id = ctx.mme_ue_add(enb_ue_id);
        ctx.enb_ue_associate_mme_ue(enb_ue_id, mme_ue_id);
        let mut sessions = Vec::new();
        for (ebi, dl, ul) in [(5u8, 3_000_000u64, 1_000_000u64), (6, 4_000_000, 2_000_000)] {
            let sess_id = ctx.sess_add(mme_ue_id, ebi);
            let bearer_id = ctx.bearer_add(sess_id, mme_ue_id);
            {
                let mut pool = ctx.bearer_pool.write().unwrap();
                let b = pool.get_mut(&bearer_id).unwrap();
                b.ebi = ebi;
                b.sgw_s1u_teid = 0x8690 + u32::from(ebi);
                b.sgw_s1u_ip.ipv4 = Some([10, 0, 0, 2]);
            }
            {
                let mut pool = ctx.sess_pool.write().unwrap();
                let s = pool.get_mut(&sess_id).unwrap();
                s.bearer_list.push(bearer_id);
                s.ambr.downlink = dl;
                s.ambr.uplink = ul;
            }
            sessions.push((sess_id, bearer_id));
        }
        {
            let mut pool = ctx.mme_ue_pool.write().unwrap();
            let ue = pool.get_mut(&mme_ue_id).unwrap();
            ue.sess_list = sessions.iter().map(|(s, _)| *s).collect();
            ue.ambr.downlink = 100_000_000;
            ue.ambr.uplink = 100_000_000;
        }
        crate::s1ap_path::tap_enb_for_test(enb_id);
        let _ = crate::s1ap_path::take_tapped_for_test(enb_id);
        let (sess_id, bearer_id) = sessions[1];
        nas_eps_send_activate_default_bearer_context_request(
            &ctx,
            &ctx.bearer_find_by_id(bearer_id).unwrap(),
            &ctx.sess_find_by_id(sess_id).unwrap(),
            &ctx.mme_ue_find_by_id(mme_ue_id).unwrap(),
            &ctx.enb_ue_find_by_id(enb_ue_id).unwrap(),
            GtpCreateAction::InPdnConnectivity,
        )
        .expect("sent");
        let ambr = crate::s1ap_path::take_tapped_for_test(enb_id)
            .into_iter()
            .find_map(|pdu| match nextgcore_s1ap_gen::decode(&pdu) {
                Ok(g::S1AP_PDU::InitiatingMessage(g::InitiatingMessage {
                    value: g::InitiatingMessageValue::Id_E_RABSetup(req),
                    ..
                })) => req.protocol_i_es.0.into_iter().find_map(|ie| match ie.value {
                    g::E_RABSetupRequestProtocolIEs_EntryValue::Id_uEaggregateMaximumBitrate(a) => {
                        Some((a.u_eaggregate_maximum_bit_rate_dl.0, a.u_eaggregate_maximum_bit_rate_ul.0))
                    }
                    _ => None,
                }),
                _ => None,
            })
            .expect("an E-RAB SETUP REQUEST with a UE-AMBR");
        assert_eq!(
            ambr,
            (7_000_000, 3_000_000),
            "the sum of both active APN-AMBRs"
        );
    }

    /// #46 criterion 3: the SUBSCRIPTION wins, then the configured value, then the
    /// 3600 that used to be hardcoded.
    ///
    /// The order is the whole point: a subscription that states a timer must not be
    /// overridden by an operator default, and a deployment that configures neither must
    /// behave exactly as it did before this issue.
    #[test]
    fn t3412_prefers_the_subscription_then_the_configured_value() {
        assert_eq!(t3412_from(720, 1800), 720, "the subscription wins");
        assert_eq!(t3412_from(0, 1800), 1800, "then the configured value");
        assert_eq!(t3412_from(0, 0), 3600, "then the shipped default");
        assert_ne!(
            t3412_from(720, 1800),
            3600,
            "a subscribed timer must not silently become the old hardcoded value"
        );
    }

    /// #497: a standalone downlink ESM message leaves the MME protected under the
    /// UE's LIVE EPS security context. Checked independently of
    /// `nas_eps_security_encode`: the MAC is recomputed straight from TS 33.401
    /// Annex B.2.3 (128-EIA2: AES-CMAC over COUNT || BEARER || DIRECTION || 0^26 ||
    /// SN || ciphered message) and the body deciphered from Annex B.1.3 (128-EEA2:
    /// AES-CTR, counter COUNT || BEARER || DIRECTION || 0^90), both with
    /// `nextgcore_crypt` directly, downlink direction 1, NAS bearer 0 (TS 24.301
    /// §4.4.3.1). Two messages in a row prove the pool's downlink COUNT advances,
    /// which a snapshot of the UE could not do.
    #[test]
    fn standalone_esm_is_protected_under_the_live_context() {
        let ctx = MmeContext::new();
        let id = ctx.mme_ue_add(1);
        let (k_int, k_enc) = ([0x11u8; 16], [0x22u8; 16]);
        {
            let mut pool = ctx.mme_ue_pool.write().unwrap();
            let ue = pool.get_mut(&id).unwrap();
            ue.selected_int_algorithm = 2;
            ue.selected_enc_algorithm = 2;
            ue.knas_int = k_int;
            ue.knas_enc = k_enc;
            ue.dl_count = 0x0000_0102; // overflow 1, SN 2
        }
        let plain = esm_build::build_esm_information_request(0);
        for (n, expected_count) in [0x0000_0102u32, 0x0000_0103].into_iter().enumerate() {
            let secured = protect_esm(&ctx, id, &plain).expect("protects");
            // Security header type 2 (integrity protected and ciphered), PD 7.
            assert_eq!(secured[0], 0x27, "message {n}");
            assert_eq!(
                secured[5], expected_count as u8,
                "NAS sequence number, message {n}"
            );
            assert_ne!(
                &secured[6..],
                &plain[..],
                "the body is ciphered, message {n}"
            );

            let mut block = expected_count.to_be_bytes().to_vec();
            block.extend_from_slice(&[1 << 2, 0, 0, 0]); // BEARER 0, DIRECTION 1 (downlink)
            block.extend_from_slice(&secured[5..]); // SN || ciphered message
            let mac = nextgcore_crypt::aes_cmac::aes_cmac_calculate(&k_int, &block);
            assert_eq!(&secured[1..5], &mac[..4], "MAC verifies, message {n}");

            let mut iv = [0u8; 16];
            iv[..4].copy_from_slice(&expected_count.to_be_bytes());
            iv[4] = 1 << 2;
            let mut deciphered = vec![0u8; secured.len() - 6];
            nextgcore_crypt::aes::aes_ctr128_encrypt(
                &k_enc,
                &mut iv,
                &secured[6..],
                &mut deciphered,
            )
            .expect("EEA2");
            assert_eq!(deciphered, plain, "body deciphers, message {n}");
        }
        assert_eq!(
            ctx.mme_ue_pool.read().unwrap().get(&id).unwrap().dl_count,
            0x0000_0104,
            "the live context's downlink COUNT advanced once per message"
        );
    }

    #[test]
    fn test_nas_error_display() {
        assert_eq!(format!("{}", NasError::UeNotFound), "UE context not found");
        assert_eq!(
            format!("{}", NasError::EnbUeNotFound),
            "eNB UE context not found"
        );
        assert_eq!(format!("{}", NasError::BuildFailed), "Message build failed");
    }

    #[test]
    fn test_gtp_create_action_default() {
        let action: GtpCreateAction = Default::default();
        assert_eq!(action, GtpCreateAction::InAttachRequest);
    }

    #[test]
    fn test_send_to_enb_no_context() {
        let mme_ue = MmeUe::default();
        let enb_ue = EnbUe::default(); // id = 0

        let result = nas_eps_send_to_enb(&mme_ue, &enb_ue, vec![1, 2, 3]);
        assert_eq!(result, Err(NasError::EnbUeNotFound));
    }

    #[test]
    fn test_send_to_downlink_no_context() {
        let enb_ue = EnbUe::default(); // id = 0

        let result = nas_eps_send_to_downlink_nas_transport(&enb_ue, vec![1, 2, 3]);
        assert_eq!(result, Err(NasError::EnbUeNotFound));
    }

    #[test]
    fn test_send_emm_to_esm_empty_container() {
        let ctx = MmeContext::new();
        let enb_ue = EnbUe {
            id: 1,
            ..Default::default()
        };
        let mme_ue = MmeUe {
            id: 1,
            ..Default::default()
        };

        let result = nas_eps_send_emm_to_esm(&ctx, &enb_ue, &mme_ue, &[]);
        assert_eq!(result, Err(NasError::InvalidParameter));
    }

    #[test]
    fn test_send_emm_to_esm_no_ue() {
        let ctx = MmeContext::new();
        let enb_ue = EnbUe {
            id: 1,
            ..Default::default()
        };
        let mme_ue = MmeUe::default(); // id = 0

        let result = nas_eps_send_emm_to_esm(&ctx, &enb_ue, &mme_ue, &[1, 2, 3]);
        assert_eq!(result, Err(NasError::UeNotFound));
    }
}
