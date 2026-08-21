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

    // Build ESM activate default bearer context request
    let esm_message = esm_build::build_activate_default_bearer_context_request(
        sess,
        GtpCreateAction::InAttachRequest,
    );

    // Build EMM attach accept with ESM message
    let tai_list = vec![mme_ue.tai.clone()];
    let emm_message = emm_build::build_attach_accept(
        mme_ue,
        &esm_message,
        3600, // T3412 value in seconds
        &tai_list,
    )
    .map_err(|_| NasError::BuildFailed)?;

    // Apply security encoding
    let secured_message = nas_security::nas_eps_security_encode(
        mme_ue,
        SecurityHeaderType::IntegrityProtectedAndCiphered,
        &emm_message,
    )
    .ok_or(NasError::BuildFailed)?;

    // Store for retransmission and arm T3450 (issue #45): storing the buffer
    // without starting the timer is what left procedures outstanding forever.
    mme_ue.t3450.pkbuf = Some(secured_message.clone());
    mme_ue.t3450.start(nas_timer::T3450_DURATION);

    // Clear UE radio capability as per TS24.301
    mme_ue.ue_radio_capability.clear();

    // Build S1AP initial context setup request (APER via nextgcore-s1ap). The
    // Attach Accept NAS message travels inside this PDU, so the PDU — not the
    // bare NAS message — is what goes to the eNB (issue #42).
    let s1ap_message = s1ap_build::build_initial_context_setup_request(
        mme_ue,
        enb_ue,
        std::slice::from_ref(default_bearer),
        Some(&secured_message),
    )
    .map_err(|_| NasError::BuildFailed)?;

    nas_eps_send_to_enb(mme_ue, enb_ue, s1ap_message)
}

/// Send attach reject message
///
/// # Arguments
/// * `enb_ue` - eNB UE context
/// * `mme_ue` - MME UE context
/// * `emm_cause` - EMM cause code
/// * `esm_cause` - ESM cause code (optional)
///
/// # Returns
/// * `Ok(())` - Message sent successfully
/// * `Err(NasError)` - On error
pub fn nas_eps_send_attach_reject(
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

    nas_eps_send_to_downlink_nas_transport(enb_ue, emm_message)
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
///
/// # Returns
/// * `Ok(())` - Message sent successfully
/// * `Err(NasError)` - On error
pub fn nas_eps_send_detach_request(mme_ue: &mut MmeUe, enb_ue: &EnbUe) -> NasResult<()> {
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
        let plain_message =
            emm_build::build_detach_request(mme_ue, emm_build::DetachTypeToUe::ReAttachRequired);

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
    let plain_message = emm_build::build_tau_accept(
        mme_ue, 3600, // T3412 value
        &tai_list, 0, // EPS bearer context status
    );

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
        )
        .map_err(|_| NasError::BuildFailed)?;
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
        return nas_eps_send_attach_reject(enb_ue, mme_ue, EmmCause::EsmFailure, Some(esm_cause));
    }

    let esm_message = esm_build::build_pdn_connectivity_reject(esm_cause);

    nas_eps_send_to_downlink_nas_transport(enb_ue, esm_message)
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
    bearer: &mut MmeBearer,
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

    // Use stored message if available (retransmission)
    let esm_message = if let Some(ref pkbuf) = bearer.t3489.pkbuf {
        pkbuf.clone()
    } else {
        // Use PTI from session or default to 0
        esm_build::build_esm_information_request(0)
    };

    // Store for retransmission (T3489)
    bearer.t3489.pkbuf = Some(esm_message.clone());

    nas_eps_send_to_downlink_nas_transport(enb_ue, esm_message)
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

    let esm_message = esm_build::build_activate_default_bearer_context_request(sess, create_action);

    // Build S1AP E-RAB setup request (APER via nextgcore-s1ap). The ESM message
    // is carried inside it, so transmit the PDU (issue #42).
    let s1ap_message = s1ap_build::build_e_rab_setup_request(enb_ue, bearer, &esm_message)
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

    let esm_message = esm_build::build_activate_dedicated_bearer_context_request(bearer);

    // Build S1AP E-RAB setup request (APER via nextgcore-s1ap). The ESM message
    // is carried inside it, so transmit the PDU (issue #42).
    let s1ap_message = s1ap_build::build_e_rab_setup_request(enb_ue, bearer, &esm_message)
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

    let esm_message =
        esm_build::build_modify_bearer_context_request(bearer, qos_presence, tft_presence);

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

    let esm_message =
        esm_build::build_deactivate_bearer_context_request(bearer, EsmCause::RegularDeactivation);

    // Build S1AP E-RAB release command (APER via nextgcore-s1ap). The ESM
    // message is carried inside it, so transmit the PDU (issue #42).
    let s1ap_message = s1ap_build::build_e_rab_release_command(
        enb_ue,
        bearer.ebi,
        S1apCauseGroup::Nas,
        s1ap_build::nas_cause::NORMAL_RELEASE,
        Some(&esm_message),
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

    let esm_message = esm_build::build_bearer_resource_allocation_reject(pti, esm_cause);

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

    let esm_message = esm_build::build_bearer_resource_modification_reject(pti, esm_cause);

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
