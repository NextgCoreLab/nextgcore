//! S6a Handler Functions
//!
//! Port of src/mme/mme-s6a-handler.c - S6a message handling functions
//!
//! Implements handlers for Diameter S6a messages from HSS.

use crate::context::{Arp, Bitrate, MmeUe, Qos, SessionData};
use crate::emm_build::EmmCause;
use crate::fd_path::{
    cancellation_type, experimental_result, result_code, AiaMessage, ApnConfiguration, ClrMessage,
    IdrMessage, UlaMessage,
};

// ============================================================================
// Result Types
// ============================================================================

/// S6a handler result
pub type S6aResult<T> = Result<T, S6aError>;

/// S6a handler error types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S6aError {
    /// UE not found
    UeNotFound,
    /// Invalid message
    InvalidMessage,
    /// Authentication failed
    AuthenticationFailed,
    /// Subscription error
    SubscriptionError,
    /// Network failure
    NetworkFailure,
}

impl std::fmt::Display for S6aError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            S6aError::UeNotFound => write!(f, "UE not found"),
            S6aError::InvalidMessage => write!(f, "Invalid message"),
            S6aError::AuthenticationFailed => write!(f, "Authentication failed"),
            S6aError::SubscriptionError => write!(f, "Subscription error"),
            S6aError::NetworkFailure => write!(f, "Network failure"),
        }
    }
}

impl std::error::Error for S6aError {}

// ============================================================================
// Subscription Data Mask
// ============================================================================

/// Subscription data mask bits
pub mod subdata_mask {
    pub const MSISDN: u32 = 1 << 0;
    pub const A_MSISDN: u32 = 1 << 1;
    pub const NAM: u32 = 1 << 2;
    pub const UEAMBR: u32 = 1 << 3;
    pub const RAU_TAU_TIMER: u32 = 1 << 4;
    pub const CC: u32 = 1 << 5;
}

// ============================================================================
// Handler Functions
// ============================================================================

/// Handle Authentication Information Answer
///
/// # Arguments
/// * `mme_ue` - MME UE context
/// * `aia_message` - AIA message from HSS
///
/// # Returns
/// * `Ok(EmmCause)` - EMM cause code
/// * `Err(S6aError)` - On error
pub fn mme_s6a_handle_aia(mme_ue: &mut MmeUe, aia_message: &AiaMessage) -> S6aResult<EmmCause> {
    // Check result code
    if aia_message.result_code != result_code::DIAMETER_SUCCESS {
        log::warn!(
            "Authentication Information failed [{}]",
            aia_message.result_code
        );
        return Ok(emm_cause_from_diameter(
            Some(aia_message.result_code),
            aia_message.experimental_result_code,
        ));
    }

    // Copy authentication vector
    let vector = &aia_message.e_utran_vector;

    mme_ue.xres_len = vector.xres.len() as u8;
    if mme_ue.xres_len > 0 && mme_ue.xres_len <= 16 {
        mme_ue.xres[..mme_ue.xres_len as usize].copy_from_slice(&vector.xres);
    }

    mme_ue.kasme.copy_from_slice(&vector.kasme);
    mme_ue.rand.copy_from_slice(&vector.rand);
    mme_ue.autn.copy_from_slice(&vector.autn);

    // Clear T3460 timer
    mme_ue.t3460.pkbuf = None;

    // Update KSI
    if mme_ue.nas_eps.mme_ksi.ksi < 6 {
        mme_ue.nas_eps.mme_ksi.ksi += 1;
    } else {
        mme_ue.nas_eps.mme_ksi.ksi = 0;
    }
    mme_ue.nas_eps.ue_ksi.ksi = mme_ue.nas_eps.mme_ksi.ksi;

    log::debug!(
        "[{}] AIA handled successfully, KSI={}",
        mme_ue.imsi_bcd,
        mme_ue.nas_eps.mme_ksi.ksi
    );

    Ok(EmmCause::RequestAccepted)
}

/// Handle Update Location Answer
///
/// # Arguments
/// * `mme_ue` - MME UE context
/// * `ula_message` - ULA message from HSS
///
/// # Returns
/// * `Ok(EmmCause)` - EMM cause code
/// * `Err(S6aError)` - On error
pub fn mme_s6a_handle_ula(mme_ue: &mut MmeUe, ula_message: &UlaMessage) -> S6aResult<EmmCause> {
    // Check result code
    if ula_message.result_code != result_code::DIAMETER_SUCCESS {
        log::error!("Update Location failed [{}]", ula_message.result_code);
        return Ok(emm_cause_from_diameter(
            Some(ula_message.result_code),
            ula_message.experimental_result_code,
        ));
    }

    let subscription_data = &ula_message.subscription_data;

    // Update AMBR
    mme_ue.ambr.uplink = subscription_data.ambr_uplink;
    mme_ue.ambr.downlink = subscription_data.ambr_downlink;

    // Update MSISDN
    if !subscription_data.msisdn.is_empty() {
        mme_ue.msisdn_len = subscription_data.msisdn.len().min(15);
        mme_ue.msisdn[..mme_ue.msisdn_len]
            .copy_from_slice(&subscription_data.msisdn[..mme_ue.msisdn_len]);
        // Convert to BCD string
        mme_ue.msisdn_bcd = buffer_to_bcd(&mme_ue.msisdn[..mme_ue.msisdn_len]);
    }

    // Update network access mode
    mme_ue.network_access_mode = subscription_data.network_access_mode;

    // Update subscribed RAU/TAU timer (TS 29.272 §7.3.134).
    //
    // #46: this was a comment saying the field "would need to be added to MmeUe if
    // needed", while the shared S6a codec had been round-tripping the AVP all along
    // and both NAS accepts hardcoded 3600 s. TS 23.401 §4.3.17.3 derives T3412 from
    // this value, so dropping it told every UE to re-register on a cadence its
    // subscription had not asked for.
    mme_ue.subscribed_rau_tau_timer = subscription_data.subscribed_rau_tau_timer;
    if mme_ue.subscribed_rau_tau_timer > 0 {
        log::debug!(
            "[{}] subscribed periodic RAU/TAU timer: {} s",
            mme_ue.imsi_bcd,
            mme_ue.subscribed_rau_tau_timer
        );
    }

    // Update charging characteristics
    if let Some(cc) = subscription_data.charging_characteristics {
        // #56: the wire form is now a 4-hex-char UTF8String (TS 29.061
        // §16.4.7.2); the MME context still holds the two raw octets it means.
        mme_ue.charging_characteristics = cc.octets();
        mme_ue.charging_characteristics_presence = true;
    }

    // Process APN configurations
    let num_sessions = process_apn_configurations(mme_ue, &subscription_data.apn_configs);
    if num_sessions == 0 {
        log::error!("No session from subscription data");
        return Ok(EmmCause::SevereNetworkFailure);
    }

    mme_ue.context_identifier = subscription_data.context_identifier;

    log::debug!(
        "[{}] ULA handled successfully, {} sessions",
        mme_ue.imsi_bcd,
        num_sessions
    );

    Ok(EmmCause::RequestAccepted)
}

/// Action required after handling a Cancel-Location-Request
/// (TS 29.272 5.2.2.2 / TS 23.401 5.3.8.4)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClrAction {
    /// Network-initiated detach: send NAS Detach Request to the UE
    DetachUe {
        /// Re-attach required (CLR-Flags bit 1)
        reattach_required: bool,
    },
    /// Remove the UE context silently (UE moved to another MME/SGSN)
    RemoveContext,
    /// The UE attached afresh at another MME (#1103, TS 23.401 §5.3.2.1 step
    /// 8): delete its PDN connections at the gateways, then remove the context
    /// silently.
    DeleteSessionsAndRemove,
    /// No action required
    NoAction,
}

/// Handle Cancel Location Request
///
/// # Arguments
/// * `mme_ue` - MME UE context
/// * `clr_message` - CLR message from HSS
///
/// # Returns
/// * `Ok(ClrAction)` - Follow-up action the caller must execute
/// * `Err(S6aError)` - On error
pub fn mme_s6a_handle_clr(mme_ue: &mut MmeUe, clr_message: &ClrMessage) -> S6aResult<ClrAction> {
    log::info!(
        "[{}] Cancel Location Request, type={}",
        mme_ue.imsi_bcd,
        clr_message.cancellation_type
    );

    let reattach_required =
        clr_message.clr_flags & nextgcore_diameter::s6a::clr_flags::REATTACH_REQUIRED != 0;

    let action = match clr_message.cancellation_type {
        cancellation_type::MME_UPDATE_PROCEDURE => {
            // UE moved to another MME: old context is removed without NAS
            // signalling (TS 23.401 5.3.3.1)
            log::debug!("CLR: MME update procedure");
            mme_ue.t3470.pkbuf = None; // Clear any pending identity request
            ClrAction::RemoveContext
        }
        cancellation_type::SGSN_UPDATE_PROCEDURE => {
            // UE moved to an SGSN
            log::debug!("CLR: SGSN update procedure");
            ClrAction::RemoveContext
        }
        cancellation_type::SUBSCRIPTION_WITHDRAWAL => {
            // Subscription withdrawal: network-initiated detach
            // (TS 29.272 5.2.2.2.2)
            log::debug!("CLR: Subscription withdrawal -> network-initiated detach");
            ClrAction::DetachUe { reattach_required }
        }
        cancellation_type::INITIAL_ATTACH_PROCEDURE => {
            // UE attached at another MME (TS 23.401 §5.3.2.1 step 8): "If the
            // Cancellation Type indicates Initial Attach and there are active
            // bearer contexts in the old MME ... the old MME releases the bearer
            // contexts by sending Delete Session Request messages to the GWs
            // involved" (#1103). The other types move the PDN connections with
            // the UE, so they are not deleted.
            log::debug!("CLR: Initial attach at another MME");
            ClrAction::DeleteSessionsAndRemove
        }
        cancellation_type::UPDATE_PROCEDURE_IWF => {
            log::debug!("CLR: Update procedure IWF");
            ClrAction::RemoveContext
        }
        _ => {
            log::warn!(
                "Unknown cancellation type: {}",
                clr_message.cancellation_type
            );
            ClrAction::NoAction
        }
    };

    Ok(action)
}

/// Apply an inbound HSS-initiated request (CLR/IDR) to the UE context.
///
/// For CLR this triggers the network-initiated detach (NAS Detach Request to
/// the UE, T3422 armed) or silent context removal, per the cancellation type.
pub fn mme_s6a_process_inbound(inbound: &crate::fd_path::InboundS6aRequest) -> S6aResult<()> {
    use crate::fd_path::S6aMessage;

    let ctx = crate::context::mme_self();
    let ue_id = ctx
        .mme_ue_find_by_imsi(&inbound.imsi_bcd)
        .ok_or(S6aError::UeNotFound)?;

    match &inbound.message {
        S6aMessage::Clr(clr) => {
            let action = {
                let mut pool = ctx.mme_ue_pool.write().unwrap();
                let mme_ue = pool.get_mut(&ue_id).ok_or(S6aError::UeNotFound)?;
                mme_s6a_handle_clr(mme_ue, clr)?
            };
            match action {
                ClrAction::DetachUe { reattach_required } => {
                    // TS 29.272 §7.3.152 / TS 23.401 §5.3.8.4 (#733): the detach
                    // type follows the CLR-Flags Reattach-Required bit, and the
                    // detach is the supervised one (T3422, TS 24.301 §5.5.2.3).
                    let detach_type = if reattach_required {
                        crate::emm_build::DetachTypeToUe::ReAttachRequired
                    } else {
                        crate::emm_build::DetachTypeToUe::ReAttachNotRequired
                    };
                    // A retransmitted CLR while the detach it started is
                    // running changes nothing: it would resend DETACH
                    // REQUEST and reset T3422's count (#828). Only a detach a
                    // CLR started: one begun for another reason (an SGW
                    // restart, a PGW-initiated last-bearer release) has not
                    // carried the HSS's detach type, so the CLR is served: the
                    // DETACH REQUEST is resent with the CLR's type and T3422
                    // restarted (§5.5.2.3.5). That other detach has normally
                    // already deleted the PDN connections locally, so there is
                    // usually no Delete Session Request left to send.
                    let detaching_by_clr = ctx.mme_ue_find_by_id(ue_id).is_some_and(|ue| {
                        ue.nas_eps.type_ == crate::context::MmeEpsType::DetachRequestToUe
                            && ue.network_detach_by_clr
                    });
                    if detaching_by_clr {
                        log::info!(
                            "[{}] Cancel Location while the detach it started is running; \
                             ignored",
                            inbound.imsi_bcd
                        );
                        return Ok(());
                    }
                    // §5.3.8.4 step 3: the PDN connections still exist at the
                    // gateways, so each is deleted there before the local
                    // contexts go.
                    if let Err(e) = crate::gtp_path::send_delete_all_sessions(
                        ctx,
                        None,
                        ue_id,
                        crate::s11_build::GtpDeleteAction::NoAction,
                    ) {
                        log::warn!(
                            "[{}] HSS-initiated detach: Delete Session Requests not all sent: {e}",
                            inbound.imsi_bcd
                        );
                    }
                    let outcome = crate::network_detach::mme_initiated_detach(
                        ctx,
                        ue_id,
                        detach_type,
                        "a Cancel Location (subscription withdrawal) from the HSS",
                    );
                    if outcome == crate::network_detach::DetachOutcome::DetachRequestSent {
                        if let Some(ue) = ctx.mme_ue_pool.write().unwrap().get_mut(&ue_id) {
                            ue.network_detach_by_clr = true;
                        }
                    }
                    log::info!(
                        "[{}] HSS-initiated detach ({detach_type:?}, Reattach-Required={}): \
                         {outcome:?}",
                        inbound.imsi_bcd,
                        reattach_required
                    );
                }
                ClrAction::RemoveContext => {
                    ctx.mme_ue_remove(ue_id);
                }
                ClrAction::DeleteSessionsAndRemove => {
                    if let Err(e) = crate::gtp_path::send_delete_all_sessions(
                        ctx,
                        None,
                        ue_id,
                        crate::s11_build::GtpDeleteAction::NoAction,
                    ) {
                        log::warn!(
                            "[{}] Cancel Location (initial attach elsewhere): Delete Session \
                             Requests not all sent: {e}",
                            inbound.imsi_bcd
                        );
                    }
                    let enb_ue = ctx
                        .mme_ue_find_by_id(ue_id)
                        .map(|ue| ue.enb_ue_id)
                        .and_then(|id| ctx.enb_ue_find_by_id(id))
                        .filter(|e| e.mme_ue_id == ue_id);
                    crate::network_detach::delete_pdn_connections_locally(ctx, ue_id);
                    ctx.mme_ue_remove(ue_id);
                    // The UE is at the other MME: an S1 connection left here is
                    // stale.
                    if let Some(enb_ue) = enb_ue {
                        crate::nas_dispatch::release_ue_context(ctx, &enb_ue);
                    }
                }
                ClrAction::NoAction => {}
            }
            Ok(())
        }
        S6aMessage::Idr(idr) => {
            let (before, after) = {
                let mut pool = ctx.mme_ue_pool.write().unwrap();
                let mme_ue = pool.get_mut(&ue_id).ok_or(S6aError::UeNotFound)?;
                let before = crate::s1ap_build::ue_ambr_of(ctx, mme_ue);
                mme_s6a_handle_idr(mme_ue, idr)?;
                (before, crate::s1ap_build::ue_ambr_of(ctx, mme_ue))
            };
            // #811, TS 23.401 §5.4.2.2: when the subscribed UE-AMBR changes for
            // an ECM-CONNECTED UE, the eNB is told the new UE-AMBR with UE
            // CONTEXT MODIFICATION (TS 36.413 §8.3.4). An ECM-IDLE UE gets it
            // in its next Initial Context Setup.
            if after != before {
                for send in signal_ue_ambr(ctx, ue_id, &inbound.imsi_bcd) {
                    crate::s1ap_path::s1ap_send(send);
                }
            }
            Ok(())
        }
        _ => Err(S6aError::InvalidMessage),
    }
}

/// UEs whose UE-AMBR change waits for a procedure in progress (an index over
/// `MmeUe::ue_ambr_deferred`, so the S1AP dispatch does not walk every UE).
static UE_AMBR_DEFERRED: std::sync::Mutex<Vec<u64>> = std::sync::Mutex::new(Vec::new());

/// Why a UE CONTEXT MODIFICATION REQUEST for the UE-AMBR must wait, if it must:
/// an INITIAL CONTEXT SETUP or an S1 handover is in progress on `enb_ue`, and the
/// in-flight procedure carries a UE-AMBR computed before the change (#869
/// review). The eNB could fail the modification (TS 36.413 §8.3.4.3) or the
/// handover would install the old value at the target.
fn ue_ambr_blocked(
    ctx: &crate::context::MmeContext,
    mme_ue: &MmeUe,
    enb_ue: &crate::context::EnbUe,
) -> Option<&'static str> {
    if mme_ue.ics_pending_on == enb_ue.id {
        return Some("an Initial Context Setup is in progress");
    }
    // The source context names its target for the whole preparation (set at
    // HANDOVER REQUIRED, cleared at Notify, Cancel, Failure and expiry), so no
    // scan of the pool is needed (#916 review).
    let _ = ctx;
    (enb_ue.target_ue_id != crate::context::NEXTGCORE_INVALID_POOL_ID)
        .then_some("an S1 handover is in progress")
}

/// Tell the eNB serving `ue_id` its current UE-AMBR (TS 23.401 §5.4.2.2, UE
/// CONTEXT MODIFICATION, TS 36.413 §8.3.4). Nothing for an ECM-IDLE UE: its next
/// Initial Context Setup carries the value. Deferred while an Initial Context
/// Setup or S1 handover is in progress; [`deferred_ue_ambr_sends`] sends it when
/// that ends.
pub fn signal_ue_ambr(
    ctx: &crate::context::MmeContext,
    ue_id: u64,
    imsi: &str,
) -> Vec<crate::s1ap_handler::S1apSend> {
    let Some(mme_ue) = ctx.mme_ue_find_by_id(ue_id) else {
        return Vec::new();
    };
    // #961 review: an S1 connection being released (UE CONTEXT RELEASE COMMAND
    // sent, or waiting for the Release Access Bearers Response, TS 23.401
    // §5.3.5) is as good as gone: the UE is going ECM-IDLE, and a modification
    // sent now would race the release (TS 36.413 §8.3.4 on a context the eNB is
    // dropping). Every path that starts a release marks `ue_ctx_rel_action`.
    let Some(enb_ue) = ctx
        .enb_ue_find_by_id(mme_ue.enb_ue_id)
        .filter(|e| e.mme_ue_id == ue_id)
        .filter(|e| e.ue_ctx_rel_action == crate::context::UeCtxRelAction::Invalid)
    else {
        // #916 review: nothing is left to defer either. A change deferred
        // before the UE went ECM-IDLE is dropped here, once: the next Initial
        // Context Setup carries the current value, and a deferral kept would
        // log on every pass and send a redundant modification later.
        let was_deferred = ctx
            .mme_ue_pool
            .write()
            .unwrap()
            .get_mut(&ue_id)
            .is_some_and(|ue| std::mem::take(&mut ue.ue_ambr_deferred));
        if !was_deferred {
            log::info!(
                "[{imsi}] UE-AMBR changed while ECM-IDLE or during an S1 release: the next \
                 Initial Context Setup carries it"
            );
        }
        return Vec::new();
    };
    if let Some(why) = ue_ambr_blocked(ctx, &mme_ue, &enb_ue) {
        log::info!("[{imsi}] UE-AMBR change deferred: {why}");
        if let Some(ue) = ctx.mme_ue_pool.write().unwrap().get_mut(&ue_id) {
            ue.ue_ambr_deferred = true;
        }
        // #1109: the index belongs to the process-wide context (ids of other
        // contexts overlap its own).
        if std::ptr::eq(ctx, crate::context::mme_self()) {
            let mut index = UE_AMBR_DEFERRED.lock().unwrap_or_else(|e| e.into_inner());
            if !index.contains(&ue_id) {
                index.push(ue_id);
            }
        }
        return Vec::new();
    }
    let ambr = crate::s1ap_build::ue_ambr_of(ctx, &mme_ue);
    match crate::s1ap_build::build_ue_context_modification_for_ue_ambr(&enb_ue, ambr) {
        Ok(pdu) => {
            log::info!(
                "[{imsi}] UE-AMBR changed: UE CONTEXT MODIFICATION REQUEST with UE-AMBR {}/{} \
                 bit/s (TS 23.401 §5.4.2.2)",
                ambr.dl,
                ambr.ul
            );
            if let Some(ue) = ctx.mme_ue_pool.write().unwrap().get_mut(&ue_id) {
                ue.ue_ambr_deferred = false;
                ue.ue_ambr_modification_pending = true;
            }
            vec![crate::s1ap_handler::S1apSend {
                enb_id: enb_ue.enb_id,
                pdu,
            }]
        }
        Err(e) => {
            log::error!("[{imsi}] UE Context Modification Request not built: {e}");
            Vec::new()
        }
    }
}

/// The UE-AMBR changes deferred by [`signal_ue_ambr`] whose blocking procedure
/// has ended, as UE CONTEXT MODIFICATION REQUESTs. Called after each S1AP
/// message and handover-preparation sweep; free when nothing is deferred.
pub fn deferred_ue_ambr_sends(
    ctx: &crate::context::MmeContext,
) -> Vec<crate::s1ap_handler::S1apSend> {
    // #1109: the index names UEs of the process-wide context. A unit test's
    // own context (`handle_s1ap_message(&local, ..)`) must neither signal them
    // nor purge them because it has no UE under their ids.
    if !std::ptr::eq(ctx, crate::context::mme_self()) {
        return Vec::new();
    }
    let ids: Vec<u64> = {
        let index = UE_AMBR_DEFERRED.lock().unwrap_or_else(|e| e.into_inner());
        if index.is_empty() {
            return Vec::new();
        }
        index.clone()
    };
    let mut out = Vec::new();
    for id in ids {
        let Some(ue) = ctx.mme_ue_find_by_id(id).filter(|ue| ue.ue_ambr_deferred) else {
            UE_AMBR_DEFERRED
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .retain(|x| *x != id);
            continue;
        };
        let sends = signal_ue_ambr(ctx, id, &ue.imsi_bcd);
        let still = ctx
            .mme_ue_find_by_id(id)
            .is_some_and(|ue| ue.ue_ambr_deferred);
        if !still {
            UE_AMBR_DEFERRED
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .retain(|x| *x != id);
        }
        out.extend(sends);
    }
    out
}

/// Handle Insert Subscriber Data Request
///
/// # Arguments
/// * `mme_ue` - MME UE context
/// * `idr_message` - IDR message from HSS
///
/// # Returns
/// * `Ok(())` - Success
/// * `Err(S6aError)` - On error
pub fn mme_s6a_handle_idr(mme_ue: &mut MmeUe, idr_message: &IdrMessage) -> S6aResult<()> {
    log::info!(
        "[{}] Insert Subscriber Data Request, flags={}",
        mme_ue.imsi_bcd,
        idr_message.idr_flags
    );

    let subscription_data = &idr_message.subscription_data;

    // Update AMBR if present
    if subscription_data.ambr_uplink > 0 || subscription_data.ambr_downlink > 0 {
        mme_ue.ambr.uplink = subscription_data.ambr_uplink;
        mme_ue.ambr.downlink = subscription_data.ambr_downlink;
    }

    // Update MSISDN if present
    if !subscription_data.msisdn.is_empty() {
        mme_ue.msisdn_len = subscription_data.msisdn.len().min(15);
        mme_ue.msisdn[..mme_ue.msisdn_len]
            .copy_from_slice(&subscription_data.msisdn[..mme_ue.msisdn_len]);
        mme_ue.msisdn_bcd = buffer_to_bcd(&mme_ue.msisdn[..mme_ue.msisdn_len]);
    }

    // Update network access mode if present
    if subscription_data.network_access_mode > 0 {
        mme_ue.network_access_mode = subscription_data.network_access_mode;
    }

    // Process APN configurations if present
    if !subscription_data.apn_configs.is_empty() {
        process_apn_configurations(mme_ue, &subscription_data.apn_configs);
    }

    Ok(())
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Convert Diameter result code to EMM cause
fn emm_cause_from_diameter(
    result_code: Option<u32>,
    experimental_result_code: Option<u32>,
) -> EmmCause {
    // Check experimental result first
    if let Some(exp_code) = experimental_result_code {
        return match exp_code {
            experimental_result::DIAMETER_ERROR_USER_UNKNOWN => EmmCause::ImsiUnknownInHss,
            experimental_result::DIAMETER_ERROR_ROAMING_NOT_ALLOWED => {
                EmmCause::RoamingNotAllowedInTa
            }
            experimental_result::DIAMETER_ERROR_UNKNOWN_EPS_SUBSCRIPTION => {
                EmmCause::NoSuitableCellsInTa
            }
            experimental_result::DIAMETER_ERROR_RAT_NOT_ALLOWED => EmmCause::RoamingNotAllowedInTa,
            experimental_result::DIAMETER_ERROR_EQUIPMENT_UNKNOWN => EmmCause::IllegalUe,
            experimental_result::DIAMETER_AUTHENTICATION_DATA_UNAVAILABLE => {
                EmmCause::NetworkFailure
            }
            _ => EmmCause::NetworkFailure,
        };
    }

    // Check result code
    if let Some(code) = result_code {
        return match code {
            result_code::DIAMETER_SUCCESS => EmmCause::RequestAccepted,
            result_code::DIAMETER_AUTHORIZATION_REJECTED => EmmCause::EpsServicesNotAllowed,
            result_code::DIAMETER_UNABLE_TO_COMPLY => EmmCause::NetworkFailure,
            _ => EmmCause::NetworkFailure,
        };
    }

    EmmCause::NetworkFailure
}

/// Record the subscribed APN configurations on the UE context.
///
/// This used to build an `MmeSess` and an `MmeBearer` as locals, log them, and
/// drop them on the floor under the comment "In actual implementation, add
/// session and bearer to UE context" — while returning a count its caller logged
/// as though they had been stored. `mme_ue.session` and `num_of_session` were
/// never assigned by anything, so a ULA reported N sessions and persisted none.
///
/// It now fills the subscription *record* (`mme_ue.session`), which is what that
/// field is for. Turning the record into session and bearer contexts needs
/// `MmeContext`, which this function deliberately does not have — see
/// [`materialise_subscribed_sessions`].
fn process_apn_configurations(mme_ue: &mut MmeUe, apn_configs: &[ApnConfiguration]) -> usize {
    mme_ue.session.clear();

    for apn_config in apn_configs {
        if mme_ue.session.len() >= crate::context::NEXTGCORE_MAX_NUM_OF_SESS {
            log::warn!(
                "[{}] subscription has more than {} APNs; ignoring the rest",
                mme_ue.imsi_bcd,
                crate::context::NEXTGCORE_MAX_NUM_OF_SESS
            );
            break;
        }

        log::debug!(
            "[{}] subscribed APN '{}' (QCI {}, AMBR {}/{} bps)",
            mme_ue.imsi_bcd,
            apn_config.service_selection,
            apn_config.qci,
            apn_config.ambr_uplink,
            apn_config.ambr_downlink
        );

        mme_ue.session.push(SessionData {
            name: apn_config.service_selection.clone(),
            pdn_type: apn_config.pdn_type,
            qos: Qos {
                qci: apn_config.qci,
                arp: Arp {
                    priority_level: apn_config.arp_priority_level,
                    // TS 29.212: the Diameter booleans are ENABLED, which the
                    // NAS/GTP encoding spells as 0.
                    pre_emption_capability: u8::from(!apn_config.arp_pre_emption_capability),
                    pre_emption_vulnerability: u8::from(!apn_config.arp_pre_emption_vulnerability),
                },
                ..Default::default()
            },
            ambr: Bitrate {
                uplink: apn_config.ambr_uplink,
                downlink: apn_config.ambr_downlink,
            },
        });
    }

    mme_ue.num_of_session = mme_ue.session.len();
    mme_ue.num_of_session
}

/// Turn the subscribed APNs into session and bearer contexts.
///
/// Separate from [`process_apn_configurations`] because it needs `MmeContext`,
/// and because the caller has to have dropped the `mme_ue_pool` guard first: the
/// links run in both directions (`mme_ue.sess_list`, `sess.bearer_list`), so this
/// takes that lock itself.
///
/// Idempotent: a UE that already has SUBSCRIBED sessions is left alone, so a
/// retransmitted procedure cannot double-allocate. The session the UE's own PDN
/// CONNECTIVITY REQUEST created does not count: it exists before the ULA in every
/// attach, and treating it as "already has sessions" left nothing to pair it with,
/// so every attach was rejected #19 (#479). Returns how many subscribed sessions
/// the UE has.
pub fn materialise_subscribed_sessions(ctx: &crate::context::MmeContext, mme_ue_id: u64) -> usize {
    let Some(mme_ue) = ctx.mme_ue_find_by_id(mme_ue_id) else {
        return 0;
    };
    let subscribed = mme_ue
        .sess_list
        .iter()
        .filter_map(|id| ctx.sess_find_by_id(*id))
        .filter(|sess| sess.session.is_some())
        .count();
    if subscribed != 0 {
        return subscribed;
    }

    let mut created = 0;
    for (index, subscribed) in mme_ue.session.iter().enumerate() {
        // PTI 0: these sessions come from the subscription, not from a UE
        // procedure transaction (TS 24.301 §9.9.4.15 reserves 0 for exactly
        // "no procedure transaction identity assigned").
        let sess_id = ctx.sess_add(mme_ue_id, 0);
        let bearer_id = ctx.bearer_add(sess_id, mme_ue_id);

        // EBIs are allocated from the bottom of the range (TS 24.007 §11.2.3.1.5
        // reserves 0-4), one per default bearer.
        let ebi = crate::context::MIN_EPS_BEARER_ID + index as u8;

        if let Some(sess) = ctx.sess_pool.write().unwrap().get_mut(&sess_id) {
            sess.apn = subscribed.name.clone();
            sess.ambr = subscribed.ambr.clone();
            sess.session = Some(subscribed.clone());
            sess.bearer_list.push(bearer_id);
        }
        if let Some(bearer) = ctx.bearer_pool.write().unwrap().get_mut(&bearer_id) {
            bearer.ebi = ebi;
            bearer.qos = subscribed.qos.clone();
        }
        if let Some(mme_ue) = ctx.mme_ue_pool.write().unwrap().get_mut(&mme_ue_id) {
            mme_ue.sess_list.push(sess_id);
        }

        log::info!(
            "[{}] session for APN '{}' with default bearer EBI {ebi}",
            mme_ue.imsi_bcd,
            subscribed.name
        );
        created += 1;
    }

    created
}

/// Match the APN the UE asked for against the subscription (TS 23.401 §5.3.2.1).
///
/// The UE's request arrives as an ESM PDN CONNECTIVITY REQUEST, which
/// `nas_dispatch` turns into a session carrying the UE's procedure transaction
/// identity; the subscribed APNs are the sessions
/// [`materialise_subscribed_sessions`] created with PTI 0. This pairs them.
///
/// `Ok(sess_id)` is the subscribed session to activate, with the UE's PTI and
/// requested PDN type copied onto it. `Err(cause)` is what the UE is owed:
/// TS 24.301 §6.5.1.4 gives ESM cause #27 for an APN the subscription does not
/// contain, and #33 when the subscription contains nothing at all.
pub fn reconcile_requested_apn(
    ctx: &crate::context::MmeContext,
    mme_ue_id: u64,
) -> Result<u64, crate::esm_build::EsmCause> {
    use crate::esm_build::EsmCause;

    let sessions: Vec<crate::context::MmeSess> = ctx
        .mme_ue_find_by_id(mme_ue_id)
        .map(|mme_ue| {
            mme_ue
                .sess_list
                .iter()
                .filter_map(|id| ctx.sess_find_by_id(*id))
                .collect()
        })
        .unwrap_or_default();

    // What the UE asked for: the session `nas_dispatch` created for its
    // procedure transaction. An empty APN means "give me the default".
    let requested = sessions
        .iter()
        .find(|sess| sess.pti != 0)
        .map(|sess| (sess.pti, sess.ue_request_pdn_type, sess.apn.clone()));

    let subscribed: Vec<&crate::context::MmeSess> =
        sessions.iter().filter(|sess| sess.pti == 0).collect();
    if subscribed.is_empty() {
        return Err(EsmCause::RequestedServiceOptionNotSubscribed);
    }

    let (pti, pdn_type, requested_apn) = requested.unwrap_or_default();

    let chosen = if requested_apn.is_empty() {
        // TS 23.401 §5.3.2.1: with no APN in the request the MME uses the
        // subscriber's default. Selecting it by Context-Identifier needs a
        // per-APN context id that `SessionData` does not carry yet, so the first
        // subscribed APN stands in — the shipped subscriptions have one APN, and
        // the approximation is visible in the log rather than silent.
        log::info!("No APN requested; using the first subscribed APN as the default");
        subscribed.first().copied()
    } else {
        subscribed
            .iter()
            .copied()
            .find(|sess| sess.apn.eq_ignore_ascii_case(&requested_apn))
    };

    let Some(chosen) = chosen else {
        log::warn!("Requested APN '{requested_apn}' is not in the subscription");
        return Err(EsmCause::MissingOrUnknownApn);
    };

    // Carry the UE's transaction onto the session that will be activated, so the
    // ESM procedure that follows addresses the subscribed session rather than the
    // placeholder the request created.
    let chosen_id = chosen.id;
    if let Some(sess) = ctx.sess_pool.write().unwrap().get_mut(&chosen_id) {
        sess.pti = pti;
        sess.ue_request_pdn_type = pdn_type;
    }
    log::info!("Activating subscribed APN '{}' (pti={pti})", chosen.apn);
    Ok(chosen_id)
}

/// Convert buffer to BCD string
fn buffer_to_bcd(buffer: &[u8]) -> String {
    let mut result = String::with_capacity(buffer.len() * 2);

    for byte in buffer {
        let low = byte & 0x0f;
        let high = (byte >> 4) & 0x0f;

        if low < 10 {
            result.push((b'0' + low) as char);
        }
        if high < 10 {
            result.push((b'0' + high) as char);
        }
    }

    result
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fd_path::{EUtranVector, SubscriptionData};

    #[test]
    fn test_s6a_error_display() {
        assert_eq!(format!("{}", S6aError::UeNotFound), "UE not found");
        assert_eq!(
            format!("{}", S6aError::AuthenticationFailed),
            "Authentication failed"
        );
    }

    #[test]
    fn test_handle_aia_success() {
        let mut mme_ue = MmeUe::default();
        mme_ue.imsi_bcd = "310260123456789".to_string();

        let aia_message = AiaMessage {
            result_code: result_code::DIAMETER_SUCCESS,
            experimental_result_code: None,
            e_utran_vector: EUtranVector {
                rand: [1u8; 16],
                xres: vec![2u8; 8],
                autn: [3u8; 16],
                kasme: [4u8; 32],
            },
        };

        let result = mme_s6a_handle_aia(&mut mme_ue, &aia_message);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), EmmCause::RequestAccepted);
        assert_eq!(mme_ue.rand, [1u8; 16]);
        assert_eq!(mme_ue.autn, [3u8; 16]);
        assert_eq!(mme_ue.kasme, [4u8; 32]);
    }

    #[test]
    fn test_handle_aia_failure() {
        let mut mme_ue = MmeUe::default();
        mme_ue.imsi_bcd = "310260123456789".to_string();

        let aia_message = AiaMessage {
            result_code: result_code::DIAMETER_UNABLE_TO_COMPLY,
            experimental_result_code: None,
            e_utran_vector: EUtranVector::default(),
        };

        let result = mme_s6a_handle_aia(&mut mme_ue, &aia_message);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), EmmCause::NetworkFailure);
    }

    #[test]
    fn test_handle_ula_success() {
        let mut mme_ue = MmeUe::default();
        mme_ue.imsi_bcd = "310260123456789".to_string();

        let ula_message = UlaMessage {
            result_code: result_code::DIAMETER_SUCCESS,
            experimental_result_code: None,
            ula_flags: 0,
            subscription_data: SubscriptionData {
                ambr_uplink: 50000000,
                ambr_downlink: 100000000,
                context_identifier: 1,
                apn_configs: vec![ApnConfiguration {
                    context_identifier: 1,
                    service_selection: "internet".to_string(),
                    pdn_type: 1, // IPv4
                    qci: 9,
                    arp_priority_level: 8,
                    ..Default::default()
                }],
                ..Default::default()
            },
        };

        let result = mme_s6a_handle_ula(&mut mme_ue, &ula_message);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), EmmCause::RequestAccepted);
        assert_eq!(mme_ue.ambr.uplink, 50000000);
        assert_eq!(mme_ue.ambr.downlink, 100000000);
    }

    #[test]
    fn test_handle_clr_mme_update_removes_context() {
        let mut mme_ue = MmeUe::default();
        mme_ue.imsi_bcd = "310260123456789".to_string();

        let clr_message = ClrMessage {
            cancellation_type: cancellation_type::MME_UPDATE_PROCEDURE,
            clr_flags: 0,
        };

        let action = mme_s6a_handle_clr(&mut mme_ue, &clr_message).unwrap();
        assert_eq!(action, ClrAction::RemoveContext);
    }

    /// Subscription withdrawal must trigger a network-initiated detach.
    #[test]
    fn test_handle_clr_subscription_withdrawal_detaches() {
        let mut mme_ue = MmeUe::default();
        mme_ue.imsi_bcd = "310260123456789".to_string();

        let clr_message = ClrMessage {
            cancellation_type: cancellation_type::SUBSCRIPTION_WITHDRAWAL,
            clr_flags: 0,
        };
        let action = mme_s6a_handle_clr(&mut mme_ue, &clr_message).unwrap();
        assert_eq!(
            action,
            ClrAction::DetachUe {
                reattach_required: false
            }
        );

        // With CLR-Flags Reattach-Required set
        let clr_message = ClrMessage {
            cancellation_type: cancellation_type::SUBSCRIPTION_WITHDRAWAL,
            clr_flags: nextgcore_diameter::s6a::clr_flags::REATTACH_REQUIRED,
        };
        let action = mme_s6a_handle_clr(&mut mme_ue, &clr_message).unwrap();
        assert_eq!(
            action,
            ClrAction::DetachUe {
                reattach_required: true
            }
        );
    }

    #[test]
    fn test_process_inbound_clr_unknown_ue() {
        let inbound = crate::fd_path::InboundS6aRequest {
            imsi_bcd: "999990000000001".to_string(),
            message: crate::fd_path::S6aMessage::Clr(ClrMessage {
                cancellation_type: cancellation_type::SUBSCRIPTION_WITHDRAWAL,
                clr_flags: 0,
            }),
        };
        // No such UE in the context: must report UeNotFound, not panic
        assert_eq!(
            mme_s6a_process_inbound(&inbound).unwrap_err(),
            S6aError::UeNotFound
        );
    }

    /// Seed a connected UE on the process-global context under a dedicated
    /// IMSI, which is how these tests stay isolated from each other (the context
    /// is keyed by IMSI).
    fn seed_connected_ue(imsi: &str, enb_ue_s1ap_id: u32) -> u64 {
        let ctx = crate::context::mme_self();
        let enb_id = ctx.enb_add(format!("127.0.0.1:{}", 36412).parse().unwrap());
        let enb_ue_id = ctx.enb_ue_add(enb_id, enb_ue_s1ap_id);
        let mme_ue_id = ctx.mme_ue_add(enb_ue_id);
        ctx.enb_ue_associate_mme_ue(enb_ue_id, mme_ue_id);
        ctx.mme_ue_set_imsi(mme_ue_id, imsi);
        mme_ue_id
    }

    /// A connected UE with one active 1 Gbit/s APN and a 1 Gbit/s subscribed
    /// UE-AMBR, its eNB tapped. Returns (MME UE id, eNB UE id, an ISD builder, a
    /// reader of the UE-AMBRs in UE CONTEXT MODIFICATION REQUESTs sent).
    #[allow(clippy::type_complexity)]
    fn ue_ambr_fixture(
        imsi: &'static str,
        s1ap_id: u32,
    ) -> (
        u64,
        u64,
        impl Fn(u64, u64) -> crate::fd_path::InboundS6aRequest,
        impl Fn() -> Vec<(u64, u64)>,
    ) {
        use nextgcore_s1ap_gen::generated as g;
        let mme_ue_id = seed_connected_ue(imsi, s1ap_id);
        let ctx = crate::context::mme_self();
        let enb_ue_id = ctx.mme_ue_find_by_id(mme_ue_id).unwrap().enb_ue_id;
        let enb_id = ctx.enb_ue_find_by_id(enb_ue_id).unwrap().enb_id;
        // One active APN of 1 Gbit/s; subscribed UE-AMBR 1 Gbit/s.
        let sess_id = ctx.sess_add(mme_ue_id, 1);
        let bearer_id = ctx.bearer_add(sess_id, mme_ue_id);
        {
            let mut pool = ctx.bearer_pool.write().unwrap();
            let b = pool.get_mut(&bearer_id).unwrap();
            b.ebi = 5;
            b.sgw_s1u_teid = 0x811;
        }
        {
            let mut pool = ctx.sess_pool.write().unwrap();
            let s = pool.get_mut(&sess_id).unwrap();
            s.bearer_list.push(bearer_id);
            s.ambr.downlink = 1_000_000_000;
            s.ambr.uplink = 1_000_000_000;
        }
        {
            let mut pool = ctx.mme_ue_pool.write().unwrap();
            let ue = pool.get_mut(&mme_ue_id).unwrap();
            ue.sess_list.push(sess_id);
            ue.ambr.downlink = 1_000_000_000;
            ue.ambr.uplink = 1_000_000_000;
        }
        crate::s1ap_path::tap_enb_for_test(enb_id);
        let _ = crate::s1ap_path::take_tapped_for_test(enb_id);
        let isd = move |dl: u64, ul: u64| crate::fd_path::InboundS6aRequest {
            imsi_bcd: imsi.to_string(),
            message: crate::fd_path::S6aMessage::Idr(crate::fd_path::IdrMessage {
                idr_flags: 0,
                subscription_data: crate::fd_path::SubscriptionData {
                    ambr_downlink: dl,
                    ambr_uplink: ul,
                    ..Default::default()
                },
            }),
        };
        let ue_ctx_mods = move || -> Vec<(u64, u64)> {
            crate::s1ap_path::take_tapped_for_test(enb_id)
                .into_iter()
                .filter_map(|pdu| match nextgcore_s1ap_gen::decode(&pdu) {
                    Ok(g::S1AP_PDU::InitiatingMessage(g::InitiatingMessage {
                        value: g::InitiatingMessageValue::Id_UEContextModification(req),
                        ..
                    })) => req.protocol_i_es.0.into_iter().find_map(|ie| match ie.value {
                        g::UEContextModificationRequestProtocolIEs_EntryValue::Id_uEaggregateMaximumBitrate(a) => {
                            Some((a.u_eaggregate_maximum_bit_rate_dl.0, a.u_eaggregate_maximum_bit_rate_ul.0))
                        }
                        _ => None,
                    }),
                    _ => None,
                })
                .collect()
        };
        (mme_ue_id, enb_ue_id, isd, ue_ctx_mods)
    }

    /// #869 review MAJOR, TS 23.401 §5.4.2.2: an Insert Subscriber Data that
    /// changes the subscribed UE-AMBR of an ECM-CONNECTED UE reaches the eNB in
    /// a UE CONTEXT MODIFICATION REQUEST carrying the recomputed UE-AMBR; one
    /// that leaves it unchanged sends nothing.
    #[test]
    fn a_subscribed_ue_ambr_change_is_signalled_to_the_enb() {
        let _guard = crate::gtp_path::lock_s11();
        const IMSI: &str = "999990000000811";
        let (mme_ue_id, _, isd, ue_ctx_mods) = ue_ambr_fixture(IMSI, 811);
        let ctx = crate::context::mme_self();
        // Lowered to 10 / 5 Mbit/s: the eNB is told.
        mme_s6a_process_inbound(&isd(10_000_000, 5_000_000)).unwrap();
        assert_eq!(ue_ctx_mods(), vec![(10_000_000, 5_000_000)]);
        // The same value again: nothing to tell.
        mme_s6a_process_inbound(&isd(10_000_000, 5_000_000)).unwrap();
        assert!(ue_ctx_mods().is_empty());
        ctx.mme_ue_remove(mme_ue_id);
    }

    /// #869 review: an ECM-IDLE UE is sent nothing; its next Initial Context
    /// Setup carries the recomputed UE-AMBR (`ue_ambr_of` reads the new value).
    #[test]
    fn an_idle_ue_gets_its_ue_ambr_change_at_the_next_connection() {
        let _guard = crate::gtp_path::lock_s11();
        let (mme_ue_id, _, isd, ue_ctx_mods) = ue_ambr_fixture("999990000008691", 8691);
        let ctx = crate::context::mme_self();
        ctx.mme_ue_pool
            .write()
            .unwrap()
            .get_mut(&mme_ue_id)
            .unwrap()
            .enb_ue_id = crate::context::NEXTGCORE_INVALID_POOL_ID;
        mme_s6a_process_inbound(&isd(10_000_000, 5_000_000)).unwrap();
        assert!(ue_ctx_mods().is_empty(), "nothing to an idle UE");
        let ue = ctx.mme_ue_find_by_id(mme_ue_id).unwrap();
        assert!(!ue.ue_ambr_deferred, "not deferred either: there is no S1");
        assert_eq!(
            crate::s1ap_build::ue_ambr_of(ctx, &ue),
            nextgcore_s1ap::UeAmbr {
                dl: 10_000_000,
                ul: 5_000_000
            },
            "what the next Initial Context Setup carries"
        );
        ctx.mme_ue_remove(mme_ue_id);
    }

    /// #869 review: while an Initial Context Setup is outstanding the change is
    /// deferred (the request in flight carries the earlier value, and the eNB
    /// could fail a modification racing it), then signalled once it is answered.
    #[test]
    fn a_ue_ambr_change_waits_for_the_initial_context_setup() {
        let _guard = crate::gtp_path::lock_s11();
        let (mme_ue_id, enb_ue_id, isd, ue_ctx_mods) = ue_ambr_fixture("999990000008692", 8692);
        let ctx = crate::context::mme_self();
        ctx.mme_ue_pool
            .write()
            .unwrap()
            .get_mut(&mme_ue_id)
            .unwrap()
            .ics_pending_on = enb_ue_id;
        mme_s6a_process_inbound(&isd(10_000_000, 5_000_000)).unwrap();
        assert!(ue_ctx_mods().is_empty(), "deferred");
        assert!(deferred_ue_ambr_sends(ctx).is_empty(), "still in progress");
        ctx.mme_ue_pool
            .write()
            .unwrap()
            .get_mut(&mme_ue_id)
            .unwrap()
            .ics_pending_on = 0;
        let sends = deferred_ue_ambr_sends(ctx);
        assert_eq!(sends.len(), 1, "signalled once the setup is answered");
        for send in sends {
            crate::s1ap_path::s1ap_send(send);
        }
        assert_eq!(ue_ctx_mods(), vec![(10_000_000, 5_000_000)]);
        let ue = ctx.mme_ue_find_by_id(mme_ue_id).unwrap();
        assert!(!ue.ue_ambr_deferred);
        assert!(ue.ue_ambr_modification_pending);
        assert!(deferred_ue_ambr_sends(ctx).is_empty(), "once");
        ctx.mme_ue_remove(mme_ue_id);
    }

    /// #1109: a test-local context (as the S1AP handler tests pass to
    /// `handle_s1ap_message`) has no UE under the deferred id; sweeping it must
    /// not purge the process context's deferral, which is still signalled once
    /// its Initial Context Setup is answered.
    #[test]
    fn another_context_does_not_purge_a_deferred_ue_ambr_change() {
        let _guard = crate::gtp_path::lock_s11();
        let (mme_ue_id, enb_ue_id, isd, ue_ctx_mods) = ue_ambr_fixture("999990000011091", 11091);
        let ctx = crate::context::mme_self();
        ctx.mme_ue_pool
            .write()
            .unwrap()
            .get_mut(&mme_ue_id)
            .unwrap()
            .ics_pending_on = enb_ue_id;
        mme_s6a_process_inbound(&isd(10_000_000, 5_000_000)).unwrap();
        assert!(ue_ctx_mods().is_empty(), "deferred");
        let local = crate::context::MmeContext::new();
        assert!(deferred_ue_ambr_sends(&local).is_empty(), "not its UE");
        assert!(
            UE_AMBR_DEFERRED.lock().unwrap().contains(&mme_ue_id),
            "still indexed"
        );
        ctx.mme_ue_pool
            .write()
            .unwrap()
            .get_mut(&mme_ue_id)
            .unwrap()
            .ics_pending_on = 0;
        assert_eq!(
            deferred_ue_ambr_sends(ctx).len(),
            1,
            "signalled once the setup is answered"
        );
        ctx.mme_ue_remove(mme_ue_id);
    }

    /// #869 review: during an S1 handover (a target context in preparation) the
    /// change is deferred too; the Handover Request already sent holds the old
    /// value.
    #[test]
    fn a_ue_ambr_change_waits_for_an_s1_handover() {
        let _guard = crate::gtp_path::lock_s11();
        let (mme_ue_id, enb_ue_id, isd, ue_ctx_mods) = ue_ambr_fixture("999990000008693", 8693);
        let ctx = crate::context::mme_self();
        let enb_id = ctx.enb_ue_find_by_id(enb_ue_id).unwrap().enb_id;
        let target = ctx.enb_ue_add(enb_id, crate::context::INVALID_UE_S1AP_ID);
        {
            let mut pool = ctx.enb_ue_pool.write().unwrap();
            let t = pool.get_mut(&target).unwrap();
            t.mme_ue_id = mme_ue_id;
            t.handover_prep_deadline =
                Some(std::time::Instant::now() + std::time::Duration::from_secs(10));
            pool.get_mut(&enb_ue_id).unwrap().target_ue_id = target;
        }
        mme_s6a_process_inbound(&isd(10_000_000, 5_000_000)).unwrap();
        assert!(ue_ctx_mods().is_empty(), "deferred during the handover");
        assert!(ctx.mme_ue_find_by_id(mme_ue_id).unwrap().ue_ambr_deferred);
        {
            let mut pool = ctx.enb_ue_pool.write().unwrap();
            pool.get_mut(&enb_ue_id).unwrap().target_ue_id = 0;
            pool.get_mut(&target).unwrap().handover_prep_deadline = None;
        }
        assert_eq!(deferred_ue_ambr_sends(ctx).len(), 1, "signalled after it");
        ctx.enb_ue_remove(target);
        ctx.mme_ue_remove(mme_ue_id);
    }

    /// #916 review: a change deferred behind an Initial Context Setup is dropped
    /// when that setup fails (no modification to a context being released) and
    /// when the UE goes ECM-IDLE (the next setup carries the value); either way
    /// the deferral index empties instead of being retried on every pass.
    #[test]
    fn a_deferred_ue_ambr_change_is_dropped_on_ics_failure_or_idle() {
        let _guard = crate::gtp_path::lock_s11();
        let (mme_ue_id, enb_ue_id, isd, ue_ctx_mods) = ue_ambr_fixture("999990000009161", 9161);
        let ctx = crate::context::mme_self();
        let defer = || {
            ctx.mme_ue_pool
                .write()
                .unwrap()
                .get_mut(&mme_ue_id)
                .unwrap()
                .ics_pending_on = enb_ue_id;
        };
        defer();
        mme_s6a_process_inbound(&isd(10_000_000, 5_000_000)).unwrap();
        assert!(ctx.mme_ue_find_by_id(mme_ue_id).unwrap().ue_ambr_deferred);
        let enb_ue = ctx.enb_ue_find_by_id(enb_ue_id).unwrap();
        let _ = crate::s1ap_handler::handle_initial_context_setup_failure(
            ctx,
            enb_ue.enb_id,
            &nextgcore_s1ap::InitialContextSetupFailure {
                mme_ue_s1ap_id: enb_ue.mme_ue_s1ap_id,
                enb_ue_s1ap_id: enb_ue.enb_ue_s1ap_id,
                cause: nextgcore_s1ap::Cause::RadioNetwork(
                    nextgcore_s1ap::CauseRadioNetwork::Unspecified,
                ),
            },
        );
        assert!(
            deferred_ue_ambr_sends(ctx).is_empty(),
            "nothing sent after the failure"
        );
        assert!(!ctx.mme_ue_find_by_id(mme_ue_id).unwrap().ue_ambr_deferred);

        // Deferred again, then the UE goes ECM-IDLE. The context stands in for
        // a new S1 connection: the failure's release mark is cleared (#961
        // review: a releasing connection takes no UE-AMBR change at all).
        if let Some(e) = ctx.enb_ue_pool.write().unwrap().get_mut(&enb_ue_id) {
            e.mme_ue_id = mme_ue_id;
            e.ue_ctx_rel_action = crate::context::UeCtxRelAction::Invalid;
        }
        ctx.mme_ue_pool
            .write()
            .unwrap()
            .get_mut(&mme_ue_id)
            .unwrap()
            .enb_ue_id = enb_ue_id;
        defer();
        mme_s6a_process_inbound(&isd(20_000_000, 5_000_000)).unwrap();
        assert!(ctx.mme_ue_find_by_id(mme_ue_id).unwrap().ue_ambr_deferred);
        ctx.mme_ue_pool
            .write()
            .unwrap()
            .get_mut(&mme_ue_id)
            .unwrap()
            .enb_ue_id = crate::context::NEXTGCORE_INVALID_POOL_ID;
        assert!(deferred_ue_ambr_sends(ctx).is_empty());
        assert!(
            !ctx.mme_ue_find_by_id(mme_ue_id).unwrap().ue_ambr_deferred,
            "dropped"
        );
        assert!(
            UE_AMBR_DEFERRED
                .lock()
                .unwrap()
                .iter()
                .all(|id| *id != mme_ue_id),
            "out of the index"
        );
        assert!(ue_ctx_mods().is_empty());
        ctx.mme_ue_remove(mme_ue_id);
    }

    /// #961 review: an S1 release in progress (here a UE CONTEXT RELEASE
    /// REQUEST from the eNB, TS 23.401 §5.3.5) blocks the UE-AMBR modification
    /// the same way ECM-IDLE does: a change deferred before it, and a change
    /// arriving during it, send nothing and are not kept; the next Initial
    /// Context Setup carries the value.
    #[test]
    fn an_s1_release_in_progress_takes_no_ue_ambr_modification() {
        let _guard = crate::gtp_path::lock_s11();
        let (mme_ue_id, enb_ue_id, isd, ue_ctx_mods) = ue_ambr_fixture("999990000009611", 9611);
        let ctx = crate::context::mme_self();
        ctx.mme_ue_pool
            .write()
            .unwrap()
            .get_mut(&mme_ue_id)
            .unwrap()
            .ics_pending_on = enb_ue_id;
        mme_s6a_process_inbound(&isd(10_000_000, 5_000_000)).unwrap();
        assert!(ctx.mme_ue_find_by_id(mme_ue_id).unwrap().ue_ambr_deferred);
        // The setup answered, then the eNB asks for the release before the
        // deferred change is retried.
        ctx.mme_ue_pool
            .write()
            .unwrap()
            .get_mut(&mme_ue_id)
            .unwrap()
            .ics_pending_on = 0;
        let enb_ue = ctx.enb_ue_find_by_id(enb_ue_id).unwrap();
        let _ = crate::s1ap_handler::handle_ue_context_release_request(
            ctx,
            enb_ue.enb_id,
            &nextgcore_s1ap::UeContextReleaseRequest {
                mme_ue_s1ap_id: enb_ue.mme_ue_s1ap_id,
                enb_ue_s1ap_id: enb_ue.enb_ue_s1ap_id,
                cause: nextgcore_s1ap::Cause::RadioNetwork(
                    nextgcore_s1ap::CauseRadioNetwork::UserInactivity,
                ),
            },
        );
        assert!(
            ctx.enb_ue_find_by_id(enb_ue_id).is_some(),
            "still linked until UE CONTEXT RELEASE COMPLETE"
        );
        let _ = crate::s1ap_path::take_tapped_for_test(enb_ue.enb_id);
        assert!(
            deferred_ue_ambr_sends(ctx).is_empty(),
            "nothing to a releasing context"
        );
        assert!(!ctx.mme_ue_find_by_id(mme_ue_id).unwrap().ue_ambr_deferred);
        // A change arriving during the release is not deferred either.
        mme_s6a_process_inbound(&isd(20_000_000, 5_000_000)).unwrap();
        let ue = ctx.mme_ue_find_by_id(mme_ue_id).unwrap();
        assert!(!ue.ue_ambr_deferred);
        assert!(ue_ctx_mods().is_empty());
        assert_eq!(
            crate::s1ap_build::ue_ambr_of(ctx, &ue),
            nextgcore_s1ap::UeAmbr {
                dl: 20_000_000,
                ul: 5_000_000
            },
            "what the next Initial Context Setup carries"
        );
        ctx.enb_ue_remove(enb_ue_id);
        ctx.mme_ue_remove(mme_ue_id);
    }

    /// #1005 review MINOR: the UE context release (`UeContextRemove`) blocks the
    /// UE-AMBR modification as the S1 release does. After an attach's INITIAL
    /// CONTEXT SETUP FAILURE the UE CONTEXT RELEASE COMMAND is sent and the
    /// context stays linked until its COMPLETE: a change arriving then sends
    /// nothing and is not deferred.
    #[test]
    fn a_ue_context_release_in_progress_takes_no_ue_ambr_modification() {
        let _guard = crate::gtp_path::lock_s11();
        let (mme_ue_id, enb_ue_id, isd, ue_ctx_mods) = ue_ambr_fixture("999990000010051", 10051);
        let ctx = crate::context::mme_self();
        ctx.mme_ue_pool
            .write()
            .unwrap()
            .get_mut(&mme_ue_id)
            .unwrap()
            .ics_pending_on = enb_ue_id;
        let enb_ue = ctx.enb_ue_find_by_id(enb_ue_id).unwrap();
        let out = crate::s1ap_handler::handle_initial_context_setup_failure(
            ctx,
            enb_ue.enb_id,
            &nextgcore_s1ap::InitialContextSetupFailure {
                mme_ue_s1ap_id: enb_ue.mme_ue_s1ap_id,
                enb_ue_s1ap_id: enb_ue.enb_ue_s1ap_id,
                cause: nextgcore_s1ap::Cause::RadioNetwork(
                    nextgcore_s1ap::CauseRadioNetwork::Unspecified,
                ),
            },
        );
        assert!(!out.is_empty(), "the UE CONTEXT RELEASE COMMAND");
        let released = ctx.enb_ue_find_by_id(enb_ue_id).unwrap();
        assert_eq!(
            released.ue_ctx_rel_action,
            crate::context::UeCtxRelAction::UeContextRemove,
            "an attach's setup failure removes the UE context"
        );
        assert_eq!(released.mme_ue_id, mme_ue_id, "still linked until COMPLETE");

        mme_s6a_process_inbound(&isd(30_000_000, 6_000_000)).unwrap();
        let ue = ctx.mme_ue_find_by_id(mme_ue_id).unwrap();
        assert!(!ue.ue_ambr_deferred, "not deferred");
        assert!(
            ue_ctx_mods().is_empty(),
            "nothing to a context on its way out"
        );
        assert!(deferred_ue_ambr_sends(ctx).is_empty());
        ctx.enb_ue_remove(enb_ue_id);
        ctx.mme_ue_remove(mme_ue_id);
    }

    fn clr(imsi: &str, cancellation_type: u32) -> crate::fd_path::InboundS6aRequest {
        crate::fd_path::InboundS6aRequest {
            imsi_bcd: imsi.to_string(),
            message: crate::fd_path::S6aMessage::Clr(ClrMessage {
                cancellation_type,
                clr_flags: 0,
            }),
        }
    }

    #[test]
    fn test_process_inbound_clr_subscription_withdrawal_detaches_the_ue() {
        // The effect the main-loop drain exists to produce. Before it was wired
        // the Diameter layer answered CLA correctly and the UE context was
        // untouched, so a withdrawn subscription left the UE attached.
        const IMSI: &str = "999990000000777";
        let mme_ue_id = seed_connected_ue(IMSI, 777);
        let ctx = crate::context::mme_self();

        mme_s6a_process_inbound(&clr(IMSI, cancellation_type::SUBSCRIPTION_WITHDRAWAL))
            .expect("a known UE must be applied");

        // TS 29.272 §5.2.2.2.2: subscription withdrawal is a *network-initiated
        // detach*, so the UE is told and the context survives until it accepts.
        let mme_ue = ctx
            .mme_ue_find_by_id(mme_ue_id)
            .expect("the context waits for the Detach Accept");
        let detach = mme_ue
            .t3422
            .pkbuf
            .as_ref()
            .expect("a Detach Request must be armed on T3422");
        // The stored message is security-encoded, so the plain NAS message starts
        // after the 6-octet security header and its type is octet 7.
        assert_eq!(
            detach.get(7).copied(),
            Some(crate::emm_build::NasEpsMessageType::DetachRequest as u8)
        );
    }

    /// #733, TS 29.272 §7.3.152 / TS 23.401 §5.3.8.4: the detach type of the
    /// DETACH REQUEST follows the CLR-Flags Reattach-Required bit, and the
    /// detach is the supervised one: T3422 armed, the UE in the network-detach
    /// state, so DETACH ACCEPT completes it. Before #733 the type was always
    /// "re-attach required" and T3422 never ran.
    #[test]
    fn a_cancel_location_detach_follows_reattach_required_and_arms_t3422() {
        for (imsi, enb_ue_s1ap_id, flags, expected) in [
            (
                "999990000000733",
                733,
                0,
                crate::emm_build::DetachTypeToUe::ReAttachNotRequired,
            ),
            (
                "999990000000734",
                734,
                nextgcore_diameter::s6a::clr_flags::REATTACH_REQUIRED,
                crate::emm_build::DetachTypeToUe::ReAttachRequired,
            ),
        ] {
            let mme_ue_id = seed_connected_ue(imsi, enb_ue_s1ap_id);
            let ctx = crate::context::mme_self();
            let inbound = crate::fd_path::InboundS6aRequest {
                imsi_bcd: imsi.to_string(),
                message: crate::fd_path::S6aMessage::Clr(ClrMessage {
                    cancellation_type: cancellation_type::SUBSCRIPTION_WITHDRAWAL,
                    clr_flags: flags,
                }),
            };
            mme_s6a_process_inbound(&inbound).expect("a known UE must be applied");

            let ue = ctx
                .mme_ue_find_by_id(mme_ue_id)
                .expect("waits for DETACH ACCEPT");
            assert!(ue.t3422.is_running(), "T3422 supervises the detach");
            assert_eq!(
                ue.nas_eps.type_,
                crate::context::MmeEpsType::DetachRequestToUe
            );
            assert_eq!(ue.network_detach_type, Some(expected));
            let detach = ue
                .t3422
                .pkbuf
                .as_ref()
                .expect("the DETACH REQUEST is stored");
            assert_eq!(
                detach.get(7).copied(),
                Some(crate::emm_build::NasEpsMessageType::DetachRequest as u8)
            );
            assert_eq!(
                detach.get(8).map(|o| o & 0x07),
                Some(expected as u8),
                "detach type on the wire (TS 24.301 §9.9.3.7)"
            );
            // DETACH ACCEPT now completes it and the context goes.
            assert!(crate::network_detach::complete_mme_initiated_detach(
                ctx, mme_ue_id
            ));
            assert!(ctx.mme_ue_find_by_id(mme_ue_id).is_none());
        }
    }

    /// #828 (review MINOR 1, 2), TS 23.401 §5.3.8.4 step 3: the HSS-initiated
    /// detach deletes every PDN connection at the Serving GW BEFORE the local
    /// contexts go, and one PDN that cannot be deleted (no default bearer) does
    /// not stop the others' Delete Session Requests. A retransmitted CLR while
    /// the detach runs sends nothing more.
    #[test]
    fn a_cancel_location_deletes_every_pdn_at_the_sgw_first() {
        use nextgcore_gtp::v2::{Gtp2IeType, Gtp2Message};
        let _guard = crate::gtp_path::lock_s11();
        let sgw = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        sgw.set_read_timeout(Some(std::time::Duration::from_millis(500)))
            .unwrap();
        let server = crate::gtp_path::GtpcServer::open(
            "127.0.0.1:0",
            nextgcore_gtp::v2::xact::Gtp2XactConfig::default(),
            7,
        )
        .unwrap();
        let _route = crate::gtp_path::route_s11_for_test(server, sgw.local_addr().unwrap());

        const IMSI: &str = "999990000000828";
        let mme_ue_id = seed_connected_ue(IMSI, 828);
        let ctx = crate::context::mme_self();
        let sgw_ue_id = ctx.sgw_ue_add(mme_ue_id);
        ctx.sgw_ue_pool
            .write()
            .unwrap()
            .get_mut(&sgw_ue_id)
            .unwrap()
            .sgw_s11_teid = 0x0828_0001;
        // Three PDN connections: default bearers 5 and 7, and one with none.
        let mut sessions = Vec::new();
        for ebis in [&[5u8, 6][..], &[7u8][..], &[][..]] {
            let sess_id = ctx.sess_add(mme_ue_id, 1);
            for ebi in ebis {
                let bearer_id = ctx.bearer_add(sess_id, mme_ue_id);
                ctx.bearer_pool
                    .write()
                    .unwrap()
                    .get_mut(&bearer_id)
                    .unwrap()
                    .ebi = *ebi;
                ctx.sess_pool
                    .write()
                    .unwrap()
                    .get_mut(&sess_id)
                    .unwrap()
                    .bearer_list
                    .push(bearer_id);
            }
            sessions.push(sess_id);
        }
        {
            let mut pool = ctx.mme_ue_pool.write().unwrap();
            let ue = pool.get_mut(&mme_ue_id).unwrap();
            ue.sgw_ue_id = sgw_ue_id;
            // The empty one first: its failure must not stop the others.
            ue.sess_list = vec![sessions[2], sessions[0], sessions[1]];
        }

        mme_s6a_process_inbound(&clr(IMSI, cancellation_type::SUBSCRIPTION_WITHDRAWAL))
            .expect("applied");

        let mut lbis = Vec::new();
        let mut buf = [0u8; 4096];
        while let Ok((len, _)) = sgw.recv_from(&mut buf) {
            let msg = Gtp2Message::decode(&mut bytes::Bytes::copy_from_slice(&buf[..len])).unwrap();
            if msg.header.message_type == 36 {
                assert_eq!(msg.header.teid, Some(0x0828_0001));
                lbis.push(msg.get_ie(Gtp2IeType::Ebi as u8, 0).unwrap().value[0]);
            }
        }
        lbis.sort();
        assert_eq!(
            lbis,
            vec![5, 7],
            "a Delete Session Request per deletable PDN"
        );
        let ue = ctx.mme_ue_find_by_id(mme_ue_id).unwrap();
        assert!(ue.sess_list.is_empty(), "then deleted locally");
        assert_eq!(
            ctx.sgw_ue_find_by_id(sgw_ue_id).unwrap().sgw_s11_teid,
            0,
            "the Serving GW's TEID is not reused by the next attach (#828)"
        );
        let retries = ue.t3422.retry_count;
        let stored = ue.t3422.pkbuf.clone();

        // The HSS retransmits the CLR: nothing more is sent or reset.
        mme_s6a_process_inbound(&clr(IMSI, cancellation_type::SUBSCRIPTION_WITHDRAWAL))
            .expect("applied");
        assert!(
            sgw.recv_from(&mut buf).is_err(),
            "no second Delete Session Request"
        );
        let ue = ctx.mme_ue_find_by_id(mme_ue_id).unwrap();
        assert_eq!(ue.t3422.retry_count, retries);
        assert_eq!(ue.t3422.pkbuf, stored);
        crate::network_detach::complete_mme_initiated_detach(ctx, mme_ue_id);
    }

    /// #1103, TS 23.401 §5.3.2.1 step 8: a Cancel Location for an initial
    /// attach at another MME deletes the UE's PDN connections at the Serving
    /// GW (OI set) before the context goes; an MME update moves them with the
    /// UE, so it deletes none. Before #1103 both only dropped the context.
    #[test]
    fn a_cancel_location_for_an_initial_attach_elsewhere_deletes_the_pdn_connections() {
        use nextgcore_gtp::v2::{Gtp2IeType, Gtp2IndicationIe, Gtp2Message};
        let _guard = crate::gtp_path::lock_s11();
        let sgw = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        sgw.set_read_timeout(Some(std::time::Duration::from_millis(500)))
            .unwrap();
        let server = crate::gtp_path::GtpcServer::open(
            "127.0.0.1:0",
            nextgcore_gtp::v2::xact::Gtp2XactConfig::default(),
            7,
        )
        .unwrap();
        let _route = crate::gtp_path::route_s11_for_test(server, sgw.local_addr().unwrap());
        let ctx = crate::context::mme_self();
        for (imsi, s1ap_id, cancellation, expected) in [
            (
                "999990000011031",
                11031,
                cancellation_type::INITIAL_ATTACH_PROCEDURE,
                vec![(5u8, true)],
            ),
            (
                "999990000011032",
                11032,
                cancellation_type::MME_UPDATE_PROCEDURE,
                vec![],
            ),
        ] {
            let mme_ue_id = seed_connected_ue(imsi, s1ap_id);
            let sgw_ue_id = ctx.sgw_ue_add(mme_ue_id);
            ctx.sgw_ue_pool
                .write()
                .unwrap()
                .get_mut(&sgw_ue_id)
                .unwrap()
                .sgw_s11_teid = 0x1103_0001;
            let sess_id = ctx.sess_add(mme_ue_id, 1);
            let bearer_id = ctx.bearer_add(sess_id, mme_ue_id);
            ctx.bearer_pool
                .write()
                .unwrap()
                .get_mut(&bearer_id)
                .unwrap()
                .ebi = 5;
            ctx.sess_pool
                .write()
                .unwrap()
                .get_mut(&sess_id)
                .unwrap()
                .bearer_list
                .push(bearer_id);
            {
                let mut pool = ctx.mme_ue_pool.write().unwrap();
                let ue = pool.get_mut(&mme_ue_id).unwrap();
                ue.sgw_ue_id = sgw_ue_id;
                ue.sess_list = vec![sess_id];
            }

            mme_s6a_process_inbound(&clr(imsi, cancellation)).expect("applied");

            let mut seen = Vec::new();
            let mut buf = [0u8; 4096];
            while let Ok((len, _)) = sgw.recv_from(&mut buf) {
                let msg =
                    Gtp2Message::decode(&mut bytes::Bytes::copy_from_slice(&buf[..len])).unwrap();
                if msg.header.message_type == 36 {
                    assert_eq!(msg.header.teid, Some(0x1103_0001));
                    let ind = msg.get_ie(Gtp2IeType::Indication as u8, 0).unwrap();
                    seen.push((
                        msg.get_ie(Gtp2IeType::Ebi as u8, 0).unwrap().value[0],
                        Gtp2IndicationIe::decode(&ind.value).unwrap().oi,
                    ));
                }
            }
            assert_eq!(seen, expected, "cancellation type {cancellation}");
            assert!(
                ctx.mme_ue_find_by_id(mme_ue_id).is_none(),
                "context removed"
            );
            ctx.sess_remove(sess_id);
            ctx.bearer_pool.write().unwrap().remove(&bearer_id);
            ctx.sgw_ue_pool.write().unwrap().remove(&sgw_ue_id);
        }
    }

    /// #828 follow-up: the duplicate-CLR guard covers only a detach a CLR started. A first
    /// CLR during a detach begun for another reason (here a re-attach-required detach, as an
    /// SGW restart sends) is the HSS's instruction and is served: the DETACH REQUEST is resent
    /// with the CLR's type (Reattach-Required clear: "re-attach not required"). Its
    /// retransmission is then ignored.
    #[test]
    fn a_first_cancel_location_during_another_detach_is_served() {
        use crate::emm_build::DetachTypeToUe as T;
        // The detach path can reach gtp_path (Delete Session Requests): serialised
        // with the S11 tests (#897 review).
        let _guard = crate::gtp_path::lock_s11();
        const IMSI: &str = "999990000008281";
        let mme_ue_id = seed_connected_ue(IMSI, 8281);
        let ctx = crate::context::mme_self();
        assert_eq!(
            crate::network_detach::mme_initiated_detach(
                ctx,
                mme_ue_id,
                T::ReAttachRequired,
                "a Serving GW restart"
            ),
            crate::network_detach::DetachOutcome::DetachRequestSent
        );
        assert!(
            !ctx.mme_ue_find_by_id(mme_ue_id)
                .unwrap()
                .network_detach_by_clr
        );

        mme_s6a_process_inbound(&clr(IMSI, cancellation_type::SUBSCRIPTION_WITHDRAWAL))
            .expect("applied");
        let ue = ctx
            .mme_ue_find_by_id(mme_ue_id)
            .expect("waits for DETACH ACCEPT");
        assert_eq!(ue.network_detach_type, Some(T::ReAttachNotRequired));
        assert!(ue.network_detach_by_clr);
        assert_eq!(
            ue.t3422
                .pkbuf
                .as_ref()
                .and_then(|d| d.get(8))
                .map(|o| o & 0x07),
            Some(T::ReAttachNotRequired as u8),
            "the CLR's detach type is on the wire"
        );
        let retries = ue.t3422.retry_count;
        let stored = ue.t3422.pkbuf.clone();

        // Its retransmission changes nothing: no DETACH REQUEST resent, T3422 not reset.
        ctx.mme_ue_pool
            .write()
            .unwrap()
            .get_mut(&mme_ue_id)
            .unwrap()
            .t3422
            .record_retransmission(crate::nas_timer::T3422_DURATION);
        let retries = retries + 1;
        mme_s6a_process_inbound(&clr(IMSI, cancellation_type::SUBSCRIPTION_WITHDRAWAL))
            .expect("applied");
        let ue = ctx.mme_ue_find_by_id(mme_ue_id).unwrap();
        assert_eq!(ue.t3422.retry_count, retries);
        assert_eq!(ue.t3422.pkbuf, stored);
        assert!(crate::network_detach::complete_mme_initiated_detach(
            ctx, mme_ue_id
        ));
    }

    #[test]
    fn test_process_inbound_clr_mme_update_removes_the_context_silently() {
        // TS 23.401 §5.3.3.1: the UE moved to another MME, so the old context
        // goes with no NAS signalling — there is no UE here to tell.
        const IMSI: &str = "999990000000778";
        let mme_ue_id = seed_connected_ue(IMSI, 778);
        let ctx = crate::context::mme_self();

        mme_s6a_process_inbound(&clr(IMSI, cancellation_type::MME_UPDATE_PROCEDURE))
            .expect("a known UE must be applied");

        assert!(ctx.mme_ue_find_by_id(mme_ue_id).is_none());
        assert_eq!(ctx.mme_ue_find_by_imsi(IMSI), None);
    }

    #[test]
    fn test_ula_records_the_subscribed_apns() {
        // The record was previously built as locals and dropped, so num_of_session
        // stayed 0 and a ULA reported sessions it had not stored.
        let mut mme_ue = MmeUe {
            imsi_bcd: "999990000000123".to_string(),
            ..Default::default()
        };
        let apns = vec![
            ApnConfiguration {
                context_identifier: 1,
                service_selection: "internet".to_string(),
                pdn_type: 0,
                qci: 9,
                arp_priority_level: 8,
                arp_pre_emption_capability: true,
                arp_pre_emption_vulnerability: false,
                ambr_uplink: 1_000_000,
                ambr_downlink: 2_000_000,
                ..Default::default()
            },
            ApnConfiguration {
                context_identifier: 2,
                service_selection: "ims".to_string(),
                pdn_type: 2,
                qci: 5,
                ..Default::default()
            },
        ];

        let count = process_apn_configurations(&mut mme_ue, &apns);

        assert_eq!(count, 2);
        assert_eq!(mme_ue.num_of_session, 2);
        assert_eq!(mme_ue.session[0].name, "internet");
        assert_eq!(mme_ue.session[0].qos.qci, 9);
        assert_eq!(mme_ue.session[0].ambr.downlink, 2_000_000);
        // Diameter's ENABLED booleans invert into the NAS/GTP encoding.
        assert_eq!(mme_ue.session[0].qos.arp.pre_emption_capability, 0);
        assert_eq!(mme_ue.session[0].qos.arp.pre_emption_vulnerability, 1);
        assert_eq!(mme_ue.session[1].name, "ims");
        assert_eq!(mme_ue.session[1].pdn_type, 2);

        // Re-applying a subscription replaces it rather than appending.
        assert_eq!(process_apn_configurations(&mut mme_ue, &apns), 2);
        assert_eq!(mme_ue.session.len(), 2);
    }

    #[test]
    fn test_materialise_creates_linked_sessions_and_bearers() {
        let ctx = crate::context::MmeContext::new();
        ctx.init();
        let enb_id = ctx.enb_add("127.0.0.1:36412".parse().unwrap());
        let enb_ue_id = ctx.enb_ue_add(enb_id, 900);
        let mme_ue_id = ctx.mme_ue_add(enb_ue_id);
        {
            let mut pool = ctx.mme_ue_pool.write().unwrap();
            let mme_ue = pool.get_mut(&mme_ue_id).unwrap();
            mme_ue.imsi_bcd = "999990000000124".to_string();
            mme_ue.session = vec![
                crate::context::SessionData {
                    name: "internet".to_string(),
                    qos: Qos {
                        qci: 9,
                        arp: Arp {
                            priority_level: 7,
                            ..Default::default()
                        },
                        ..Default::default()
                    },
                    ambr: Bitrate {
                        uplink: 1_000_000,
                        downlink: 4_000_000,
                    },
                    ..Default::default()
                },
                crate::context::SessionData {
                    name: "ims".to_string(),
                    ..Default::default()
                },
            ];
            mme_ue.num_of_session = 2;
        }

        assert_eq!(materialise_subscribed_sessions(&ctx, mme_ue_id), 2);

        let sess_list = ctx.mme_ue_find_by_id(mme_ue_id).unwrap().sess_list;
        assert_eq!(sess_list.len(), 2, "both sessions linked to the UE");

        let first = ctx.sess_find_by_id(sess_list[0]).unwrap();
        assert_eq!(first.apn, "internet");
        assert_eq!(first.bearer_list.len(), 1, "one default bearer per session");
        let bearer = ctx.bearer_find_by_id(first.bearer_list[0]).unwrap();
        assert_eq!(bearer.ebi, crate::context::MIN_EPS_BEARER_ID);
        assert_eq!(bearer.qos.qci, 9);
        // #46 criterion 8(a): the ARP and the APN-AMBR must survive too. The QCI
        // alone was asserted before, so a subscription whose priority or rate limit
        // was dropped looked persisted.
        assert_eq!(
            bearer.qos.arp.priority_level, 7,
            "the subscribed ARP priority must reach the bearer"
        );
        assert_eq!(
            (first.ambr.uplink, first.ambr.downlink),
            (1_000_000, 4_000_000),
            "the subscribed APN-AMBR must reach the session"
        );

        // The second session gets the next EBI, not a duplicate.
        let second = ctx.sess_find_by_id(sess_list[1]).unwrap();
        let second_bearer = ctx.bearer_find_by_id(second.bearer_list[0]).unwrap();
        assert_eq!(second_bearer.ebi, crate::context::MIN_EPS_BEARER_ID + 1);
        assert_eq!(
            ctx.bearer_find_by_ebi(mme_ue_id, crate::context::MIN_EPS_BEARER_ID + 1),
            Some(second_bearer.id)
        );

        // Idempotent: a retransmitted procedure must not double-allocate.
        assert_eq!(materialise_subscribed_sessions(&ctx, mme_ue_id), 2);
        assert_eq!(ctx.sess_pool.read().unwrap().len(), 2);
        assert_eq!(ctx.bearer_pool.read().unwrap().len(), 2);
    }

    /// #46 criterion 3: the subscribed periodic RAU/TAU timer must reach the UE
    /// context from the ULA.
    ///
    /// The S6a codec round-tripped this AVP all along and mmed dropped it under a
    /// comment saying the field "would need to be added to MmeUe if needed", so both
    /// NAS accepts signalled a hardcoded 3600 s whatever the subscription said.
    #[test]
    fn the_subscribed_rau_tau_timer_reaches_the_ue_context() {
        let mut mme_ue = MmeUe::default();
        let mut ula = UlaMessage {
            result_code: result_code::DIAMETER_SUCCESS,
            ..Default::default()
        };
        ula.subscription_data.subscribed_rau_tau_timer = 720;
        ula.subscription_data.apn_configs = vec![ApnConfiguration {
            service_selection: "internet".to_string(),
            qci: 9,
            ..Default::default()
        }];

        assert_eq!(
            mme_s6a_handle_ula(&mut mme_ue, &ula).expect("ULA handled"),
            EmmCause::RequestAccepted
        );
        assert_eq!(
            mme_ue.subscribed_rau_tau_timer, 720,
            "the subscribed timer must be recorded, not dropped"
        );
    }

    /// A subscription that states no timer leaves the field at 0, which is what makes
    /// the configured fallback reachable rather than being overwritten by a zero.
    #[test]
    fn an_absent_subscribed_timer_leaves_the_field_zero() {
        let mut mme_ue = MmeUe {
            subscribed_rau_tau_timer: 999,
            ..Default::default()
        };
        let mut ula = UlaMessage {
            result_code: result_code::DIAMETER_SUCCESS,
            ..Default::default()
        };
        ula.subscription_data.apn_configs = vec![ApnConfiguration {
            service_selection: "internet".to_string(),
            ..Default::default()
        }];

        mme_s6a_handle_ula(&mut mme_ue, &ula).expect("ULA handled");
        assert_eq!(
            mme_ue.subscribed_rau_tau_timer, 0,
            "a subscription with no timer must not leave a stale one in place"
        );
    }

    /// A UE with one subscribed APN materialised, plus the session the UE's own
    /// PDN CONNECTIVITY REQUEST created under its procedure transaction.
    fn ue_with_subscription_and_request(
        requested_apn: &str,
        pti: u8,
    ) -> (crate::context::MmeContext, u64) {
        let ctx = crate::context::MmeContext::new();
        ctx.init();
        let enb_id = ctx.enb_add("127.0.0.1:36412".parse().unwrap());
        let enb_ue_id = ctx.enb_ue_add(enb_id, 901);
        let mme_ue_id = ctx.mme_ue_add(enb_ue_id);
        {
            let mut pool = ctx.mme_ue_pool.write().unwrap();
            let mme_ue = pool.get_mut(&mme_ue_id).unwrap();
            mme_ue.imsi_bcd = "999990000000125".to_string();
            mme_ue.session = vec![crate::context::SessionData {
                name: "internet".to_string(),
                ..Default::default()
            }];
            mme_ue.num_of_session = 1;
        }
        materialise_subscribed_sessions(&ctx, mme_ue_id);

        // What nas_dispatch's ESM path leaves behind for the UE's request.
        let requested = ctx.sess_add(mme_ue_id, pti);
        if let Some(sess) = ctx.sess_pool.write().unwrap().get_mut(&requested) {
            sess.apn = requested_apn.to_string();
        }
        if let Some(mme_ue) = ctx.mme_ue_pool.write().unwrap().get_mut(&mme_ue_id) {
            mme_ue.sess_list.push(requested);
        }
        (ctx, mme_ue_id)
    }

    /// #479: in an attach the UE's own PDN CONNECTIVITY REQUEST session exists
    /// BEFORE the ULA. It must not count as "already has sessions", or nothing is
    /// materialised to pair it with and every attach is rejected #19.
    #[test]
    fn materialise_ignores_the_ues_own_request_session() {
        let ctx = crate::context::MmeContext::new();
        ctx.init();
        let mme_ue_id = ctx.mme_ue_add(1);
        let requested = ctx.sess_add(mme_ue_id, 7);
        {
            let mut pool = ctx.mme_ue_pool.write().unwrap();
            let mme_ue = pool.get_mut(&mme_ue_id).unwrap();
            mme_ue.sess_list.push(requested);
            mme_ue.session = vec![crate::context::SessionData {
                name: "internet".to_string(),
                ..Default::default()
            }];
        }

        assert_eq!(materialise_subscribed_sessions(&ctx, mme_ue_id), 1);
        let chosen = reconcile_requested_apn(&ctx, mme_ue_id).expect("subscribed APN");
        assert_ne!(chosen, requested);
        // And a second call is still idempotent.
        assert_eq!(materialise_subscribed_sessions(&ctx, mme_ue_id), 1);
    }

    #[test]
    fn test_requested_apn_matches_the_subscription() {
        let (ctx, mme_ue_id) = ue_with_subscription_and_request("internet", 3);

        let sess_id = reconcile_requested_apn(&ctx, mme_ue_id).expect("subscribed APN");

        let sess = ctx.sess_find_by_id(sess_id).unwrap();
        assert_eq!(sess.apn, "internet");
        assert_eq!(sess.pti, 3, "the UE's transaction moves onto it");
    }

    #[test]
    fn test_no_requested_apn_uses_the_default() {
        let (ctx, mme_ue_id) = ue_with_subscription_and_request("", 4);

        let sess_id = reconcile_requested_apn(&ctx, mme_ue_id).expect("default APN");

        assert_eq!(ctx.sess_find_by_id(sess_id).unwrap().apn, "internet");
    }

    #[test]
    fn test_unsubscribed_apn_is_refused_with_cause_27() {
        let (ctx, mme_ue_id) = ue_with_subscription_and_request("not-subscribed", 5);

        assert_eq!(
            reconcile_requested_apn(&ctx, mme_ue_id),
            Err(crate::esm_build::EsmCause::MissingOrUnknownApn)
        );
    }

    #[test]
    fn test_no_subscription_at_all_is_refused() {
        let ctx = crate::context::MmeContext::new();
        ctx.init();
        let mme_ue_id = ctx.mme_ue_add(1);

        assert_eq!(
            reconcile_requested_apn(&ctx, mme_ue_id),
            Err(crate::esm_build::EsmCause::RequestedServiceOptionNotSubscribed)
        );
    }

    #[test]
    fn test_handle_idr() {
        let mut mme_ue = MmeUe::default();
        mme_ue.imsi_bcd = "310260123456789".to_string();

        let idr_message = IdrMessage {
            idr_flags: 0,
            subscription_data: SubscriptionData {
                ambr_uplink: 100000000,
                ambr_downlink: 200000000,
                ..Default::default()
            },
        };

        let result = mme_s6a_handle_idr(&mut mme_ue, &idr_message);
        assert!(result.is_ok());
        assert_eq!(mme_ue.ambr.uplink, 100000000);
        assert_eq!(mme_ue.ambr.downlink, 200000000);
    }

    #[test]
    fn test_buffer_to_bcd() {
        // 123456 in TBCD: 21 43 65
        let buffer = [0x21, 0x43, 0x65];
        let bcd = buffer_to_bcd(&buffer);
        assert_eq!(bcd, "123456");
    }

    #[test]
    fn test_buffer_to_bcd_with_filler() {
        // 12345 in TBCD: 21 43 f5
        let buffer = [0x21, 0x43, 0xf5];
        let bcd = buffer_to_bcd(&buffer);
        assert_eq!(bcd, "12345"); // f is ignored
    }

    #[test]
    fn test_emm_cause_from_diameter_user_unknown() {
        let cause =
            emm_cause_from_diameter(None, Some(experimental_result::DIAMETER_ERROR_USER_UNKNOWN));
        assert_eq!(cause, EmmCause::ImsiUnknownInHss);
    }

    #[test]
    fn test_emm_cause_from_diameter_success() {
        let cause = emm_cause_from_diameter(Some(result_code::DIAMETER_SUCCESS), None);
        assert_eq!(cause, EmmCause::RequestAccepted);
    }
}
