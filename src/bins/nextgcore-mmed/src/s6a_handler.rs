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

    // Update subscribed RAU/TAU timer
    // Note: subscribed_rau_tau_timer field would need to be added to MmeUe if needed

    // Update charging characteristics
    if let Some(cc) = subscription_data.charging_characteristics {
        mme_ue.charging_characteristics = cc;
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
            // UE attached at another MME: remove the local context
            log::debug!("CLR: Initial attach at another MME");
            ClrAction::RemoveContext
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
            let (action, enb_ue_id) = {
                let mut pool = ctx.mme_ue_pool.write().unwrap();
                let mme_ue = pool.get_mut(&ue_id).ok_or(S6aError::UeNotFound)?;
                (mme_s6a_handle_clr(mme_ue, clr)?, mme_ue.enb_ue_id)
            };
            match action {
                ClrAction::DetachUe { reattach_required } => {
                    log::info!(
                        "[{}] Network-initiated detach (reattach_required={})",
                        inbound.imsi_bcd,
                        reattach_required
                    );
                    let enb_ue = ctx.enb_ue_find_by_id(enb_ue_id);
                    if let Some(enb_ue) = enb_ue {
                        let mut pool = ctx.mme_ue_pool.write().unwrap();
                        if let Some(mme_ue) = pool.get_mut(&ue_id) {
                            crate::nas_path::nas_eps_send_detach_request(mme_ue, &enb_ue).map_err(
                                |e| {
                                    log::error!(
                                        "[{}] Detach Request send failed: {e:?}",
                                        inbound.imsi_bcd
                                    );
                                    S6aError::NetworkFailure
                                },
                            )?;
                        }
                    } else {
                        // UE not connected: implicit detach, remove context
                        log::info!("[{}] UE not connected; implicit detach", inbound.imsi_bcd);
                        ctx.mme_ue_remove(ue_id);
                    }
                }
                ClrAction::RemoveContext => {
                    ctx.mme_ue_remove(ue_id);
                }
                ClrAction::NoAction => {}
            }
            Ok(())
        }
        S6aMessage::Idr(idr) => {
            let mut pool = ctx.mme_ue_pool.write().unwrap();
            let mme_ue = pool.get_mut(&ue_id).ok_or(S6aError::UeNotFound)?;
            mme_s6a_handle_idr(mme_ue, idr)
        }
        _ => Err(S6aError::InvalidMessage),
    }
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
/// Idempotent: a UE that already has sessions is left alone, so a retransmitted
/// procedure cannot double-allocate. Returns how many sessions the UE has.
pub fn materialise_subscribed_sessions(ctx: &crate::context::MmeContext, mme_ue_id: u64) -> usize {
    let Some(mme_ue) = ctx.mme_ue_find_by_id(mme_ue_id) else {
        return 0;
    };
    if !mme_ue.sess_list.is_empty() {
        return mme_ue.sess_list.len();
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
                        ..Default::default()
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
