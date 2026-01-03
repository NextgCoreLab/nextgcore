//! S6a Handler Functions
//!
//! Port of src/mme/mme-s6a-handler.c - S6a message handling functions
//!
//! Implements handlers for Diameter S6a messages from HSS.

use crate::context::{MmeUe, MmeSess, MmeBearer, Qos, Arp, Bitrate};
use crate::emm_build::EmmCause;
use crate::fd_path::{
    AiaMessage, UlaMessage, ClrMessage, IdrMessage,
    ApnConfiguration,
    result_code, experimental_result, cancellation_type,
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
pub fn mme_s6a_handle_aia(
    mme_ue: &mut MmeUe,
    aia_message: &AiaMessage,
) -> S6aResult<EmmCause> {
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
pub fn mme_s6a_handle_ula(
    mme_ue: &mut MmeUe,
    ula_message: &UlaMessage,
) -> S6aResult<EmmCause> {
    // Check result code
    if ula_message.result_code != result_code::DIAMETER_SUCCESS {
        log::error!(
            "Update Location failed [{}]",
            ula_message.result_code
        );
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

/// Handle Cancel Location Request
///
/// # Arguments
/// * `mme_ue` - MME UE context
/// * `clr_message` - CLR message from HSS
///
/// # Returns
/// * `Ok(())` - Success
/// * `Err(S6aError)` - On error
pub fn mme_s6a_handle_clr(
    mme_ue: &mut MmeUe,
    clr_message: &ClrMessage,
) -> S6aResult<()> {
    log::info!(
        "[{}] Cancel Location Request, type={}",
        mme_ue.imsi_bcd,
        clr_message.cancellation_type
    );

    match clr_message.cancellation_type {
        cancellation_type::MME_UPDATE_PROCEDURE => {
            // MME update procedure - UE moved to another MME
            log::debug!("CLR: MME update procedure");
            // Mark UE for removal
            mme_ue.t3470.pkbuf = None; // Clear any pending identity request
        }
        cancellation_type::SGSN_UPDATE_PROCEDURE => {
            // SGSN update procedure - UE moved to SGSN
            log::debug!("CLR: SGSN update procedure");
        }
        cancellation_type::SUBSCRIPTION_WITHDRAWAL => {
            // Subscription withdrawal
            log::debug!("CLR: Subscription withdrawal");
            // Initiate detach
        }
        cancellation_type::INITIAL_ATTACH_PROCEDURE => {
            // Initial attach procedure at another MME
            log::debug!("CLR: Initial attach at another MME");
        }
        _ => {
            log::warn!("Unknown cancellation type: {}", clr_message.cancellation_type);
        }
    }

    Ok(())
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
pub fn mme_s6a_handle_idr(
    mme_ue: &mut MmeUe,
    idr_message: &IdrMessage,
) -> S6aResult<()> {
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
            experimental_result::DIAMETER_ERROR_USER_UNKNOWN => {
                EmmCause::ImsiUnknownInHss
            }
            experimental_result::DIAMETER_ERROR_ROAMING_NOT_ALLOWED => {
                EmmCause::RoamingNotAllowedInTa
            }
            experimental_result::DIAMETER_ERROR_UNKNOWN_EPS_SUBSCRIPTION => {
                EmmCause::NoSuitableCellsInTa
            }
            experimental_result::DIAMETER_ERROR_RAT_NOT_ALLOWED => {
                EmmCause::RoamingNotAllowedInTa
            }
            experimental_result::DIAMETER_ERROR_EQUIPMENT_UNKNOWN => {
                EmmCause::IllegalUe
            }
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
            result_code::DIAMETER_AUTHORIZATION_REJECTED => {
                EmmCause::EpsServicesNotAllowed
            }
            result_code::DIAMETER_UNABLE_TO_COMPLY => {
                EmmCause::NetworkFailure
            }
            _ => EmmCause::NetworkFailure,
        };
    }

    EmmCause::NetworkFailure
}

/// Process APN configurations from subscription data
fn process_apn_configurations(
    mme_ue: &mut MmeUe,
    apn_configs: &[ApnConfiguration],
) -> usize {
    let mut num_sessions = 0;

    for apn_config in apn_configs {
        if num_sessions >= 4 {
            log::warn!("Max sessions reached, ignoring remaining APNs");
            break;
        }

        // Create session from APN configuration
        let sess = MmeSess {
            id: num_sessions as u64 + 1,
            pti: 0,
            apn: apn_config.service_selection.clone(),
            ambr: Bitrate {
                uplink: apn_config.ambr_uplink,
                downlink: apn_config.ambr_downlink,
            },
            ..Default::default()
        };

        // Create default bearer
        let bearer = MmeBearer {
            id: 1,
            ebi: 5 + num_sessions as u8, // EBI starts at 5
            qos: Qos {
                qci: apn_config.qci,
                arp: Arp {
                    priority_level: apn_config.arp_priority_level,
                    pre_emption_capability: if apn_config.arp_pre_emption_capability { 1 } else { 0 },
                    pre_emption_vulnerability: if apn_config.arp_pre_emption_vulnerability { 1 } else { 0 },
                },
                ..Default::default()
            },
            ..Default::default()
        };

        log::debug!(
            "Session[{}]: APN={}, QCI={}",
            num_sessions,
            sess.apn,
            bearer.qos.qci
        );

        // In actual implementation, add session and bearer to UE context
        num_sessions += 1;
    }

    num_sessions
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
        assert_eq!(format!("{}", S6aError::AuthenticationFailed), "Authentication failed");
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
                apn_configs: vec![
                    ApnConfiguration {
                        context_identifier: 1,
                        service_selection: "internet".to_string(),
                        pdn_type: 1, // IPv4
                        qci: 9,
                        arp_priority_level: 8,
                        ..Default::default()
                    },
                ],
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
    fn test_handle_clr() {
        let mut mme_ue = MmeUe::default();
        mme_ue.imsi_bcd = "310260123456789".to_string();
        
        let clr_message = ClrMessage {
            cancellation_type: cancellation_type::MME_UPDATE_PROCEDURE,
            clr_flags: 0,
        };

        let result = mme_s6a_handle_clr(&mut mme_ue, &clr_message);
        assert!(result.is_ok());
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
        let cause = emm_cause_from_diameter(
            None,
            Some(experimental_result::DIAMETER_ERROR_USER_UNKNOWN),
        );
        assert_eq!(cause, EmmCause::ImsiUnknownInHss);
    }

    #[test]
    fn test_emm_cause_from_diameter_success() {
        let cause = emm_cause_from_diameter(
            Some(result_code::DIAMETER_SUCCESS),
            None,
        );
        assert_eq!(cause, EmmCause::RequestAccepted);
    }
}
