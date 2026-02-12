//! Diameter (freeDiameter) Path Functions
//!
//! Port of src/mme/mme-fd-path.c - Diameter S6a interface functions
//!
//! Implements Diameter S6a interface for HSS communication.

use crate::context::MmeUe;
use crate::emm_build::EmmCause;

// ============================================================================
// Diameter Constants
// ============================================================================

/// Diameter Application ID for S6a
pub const DIAMETER_APPLICATION_S6A: u32 = 16777251;

/// Diameter Result Codes
pub mod result_code {
    pub const DIAMETER_SUCCESS: u32 = 2001;
    pub const DIAMETER_COMMAND_UNSUPPORTED: u32 = 3001;
    pub const DIAMETER_UNABLE_TO_DELIVER: u32 = 3002;
    pub const DIAMETER_REALM_NOT_SERVED: u32 = 3003;
    pub const DIAMETER_TOO_BUSY: u32 = 3004;
    pub const DIAMETER_LOOP_DETECTED: u32 = 3005;
    pub const DIAMETER_REDIRECT_INDICATION: u32 = 3006;
    pub const DIAMETER_APPLICATION_UNSUPPORTED: u32 = 3007;
    pub const DIAMETER_INVALID_HDR_BITS: u32 = 3008;
    pub const DIAMETER_INVALID_AVP_BITS: u32 = 3009;
    pub const DIAMETER_UNKNOWN_PEER: u32 = 3010;
    pub const DIAMETER_AUTHENTICATION_REJECTED: u32 = 4001;
    pub const DIAMETER_OUT_OF_SPACE: u32 = 4002;
    pub const DIAMETER_ELECTION_LOST: u32 = 4003;
    pub const DIAMETER_AVP_UNSUPPORTED: u32 = 5001;
    pub const DIAMETER_UNKNOWN_SESSION_ID: u32 = 5002;
    pub const DIAMETER_AUTHORIZATION_REJECTED: u32 = 5003;
    pub const DIAMETER_INVALID_AVP_VALUE: u32 = 5004;
    pub const DIAMETER_MISSING_AVP: u32 = 5005;
    pub const DIAMETER_RESOURCES_EXCEEDED: u32 = 5006;
    pub const DIAMETER_CONTRADICTING_AVPS: u32 = 5007;
    pub const DIAMETER_AVP_NOT_ALLOWED: u32 = 5008;
    pub const DIAMETER_AVP_OCCURS_TOO_MANY_TIMES: u32 = 5009;
    pub const DIAMETER_NO_COMMON_APPLICATION: u32 = 5010;
    pub const DIAMETER_UNSUPPORTED_VERSION: u32 = 5011;
    pub const DIAMETER_UNABLE_TO_COMPLY: u32 = 5012;
    pub const DIAMETER_INVALID_BIT_IN_HEADER: u32 = 5013;
    pub const DIAMETER_INVALID_AVP_LENGTH: u32 = 5014;
    pub const DIAMETER_INVALID_MESSAGE_LENGTH: u32 = 5015;
    pub const DIAMETER_INVALID_AVP_BIT_COMBO: u32 = 5016;
    pub const DIAMETER_NO_COMMON_SECURITY: u32 = 5017;
}

/// Diameter Experimental Result Codes for S6a
pub mod experimental_result {
    pub const DIAMETER_ERROR_USER_UNKNOWN: u32 = 5001;
    pub const DIAMETER_ERROR_ROAMING_NOT_ALLOWED: u32 = 5004;
    pub const DIAMETER_ERROR_UNKNOWN_EPS_SUBSCRIPTION: u32 = 5420;
    pub const DIAMETER_ERROR_RAT_NOT_ALLOWED: u32 = 5421;
    pub const DIAMETER_ERROR_EQUIPMENT_UNKNOWN: u32 = 5422;
    pub const DIAMETER_ERROR_UNKNOWN_SERVING_NODE: u32 = 5423;
    pub const DIAMETER_AUTHENTICATION_DATA_UNAVAILABLE: u32 = 4181;
}

/// S6a Command Codes
pub mod command_code {
    pub const AUTHENTICATION_INFORMATION: u32 = 318;
    pub const UPDATE_LOCATION: u32 = 316;
    pub const CANCEL_LOCATION: u32 = 317;
    pub const INSERT_SUBSCRIBER_DATA: u32 = 319;
    pub const DELETE_SUBSCRIBER_DATA: u32 = 320;
    pub const PURGE_UE: u32 = 321;
    pub const RESET: u32 = 322;
    pub const NOTIFY: u32 = 323;
}

/// S6a AVP Codes
pub mod avp_code {
    pub const USER_NAME: u32 = 1;
    pub const SESSION_ID: u32 = 263;
    pub const ORIGIN_HOST: u32 = 264;
    pub const ORIGIN_REALM: u32 = 296;
    pub const DESTINATION_HOST: u32 = 293;
    pub const DESTINATION_REALM: u32 = 283;
    pub const AUTH_SESSION_STATE: u32 = 277;
    pub const RESULT_CODE: u32 = 268;
    pub const EXPERIMENTAL_RESULT: u32 = 297;
    pub const EXPERIMENTAL_RESULT_CODE: u32 = 298;
    pub const VENDOR_ID: u32 = 266;
    
    // S6a specific AVPs
    pub const VISITED_PLMN_ID: u32 = 1407;
    pub const RAT_TYPE: u32 = 1032;
    pub const ULR_FLAGS: u32 = 1405;
    pub const ULA_FLAGS: u32 = 1406;
    pub const SUBSCRIPTION_DATA: u32 = 1400;
    pub const REQUESTED_EUTRAN_AUTHENTICATION_INFO: u32 = 1408;
    pub const NUMBER_OF_REQUESTED_VECTORS: u32 = 1410;
    pub const IMMEDIATE_RESPONSE_PREFERRED: u32 = 1412;
    pub const AUTHENTICATION_INFO: u32 = 1413;
    pub const E_UTRAN_VECTOR: u32 = 1414;
    pub const RAND: u32 = 1447;
    pub const XRES: u32 = 1448;
    pub const AUTN: u32 = 1449;
    pub const KASME: u32 = 1450;
    pub const CONTEXT_IDENTIFIER: u32 = 1423;
    pub const ALL_APN_CONFIG_INC_IND: u32 = 1428;
    pub const APN_CONFIGURATION_PROFILE: u32 = 1429;
    pub const APN_CONFIGURATION: u32 = 1430;
    pub const SERVICE_SELECTION: u32 = 493;
    pub const PDN_TYPE: u32 = 1456;
    pub const AMBR: u32 = 1435;
    pub const MAX_BANDWIDTH_UL: u32 = 516;
    pub const MAX_BANDWIDTH_DL: u32 = 515;
    pub const MSISDN: u32 = 701;
    pub const A_MSISDN: u32 = 1643;
    pub const NETWORK_ACCESS_MODE: u32 = 1417;
    pub const SUBSCRIBED_RAU_TAU_TIMER: u32 = 1619;
    pub const CHARGING_CHARACTERISTICS: u32 = 13;
    pub const EPS_SUBSCRIBED_QOS_PROFILE: u32 = 1431;
    pub const QOS_CLASS_IDENTIFIER: u32 = 1028;
    pub const ALLOCATION_RETENTION_PRIORITY: u32 = 1034;
    pub const PRIORITY_LEVEL: u32 = 1046;
    pub const PRE_EMPTION_CAPABILITY: u32 = 1047;
    pub const PRE_EMPTION_VULNERABILITY: u32 = 1048;
    pub const CANCELLATION_TYPE: u32 = 1420;
    pub const CLR_FLAGS: u32 = 1638;
    pub const IDR_FLAGS: u32 = 1490;
    pub const PUA_FLAGS: u32 = 1442;
}

/// ULR Flags
pub mod ulr_flags {
    pub const SINGLE_REGISTRATION_IND: u32 = 1 << 0;
    pub const S6A_S6D_INDICATOR: u32 = 1 << 1;
    pub const SKIP_SUBSCRIBER_DATA: u32 = 1 << 2;
    pub const GPRS_SUBSCRIPTION_DATA_IND: u32 = 1 << 3;
    pub const NODE_TYPE_IND: u32 = 1 << 4;
    pub const INITIAL_ATTACH_IND: u32 = 1 << 5;
    pub const PS_LCS_NOT_SUPPORTED_BY_UE: u32 = 1 << 6;
}

/// RAT Types
pub mod rat_type {
    pub const EUTRAN: u32 = 1004;
    pub const WLAN: u32 = 0;
    pub const VIRTUAL: u32 = 1;
    pub const UTRAN: u32 = 1000;
    pub const GERAN: u32 = 1001;
    pub const GAN: u32 = 1002;
    pub const HSPA_EVOLUTION: u32 = 1003;
    pub const EUTRAN_NB_IOT: u32 = 1005;
}

/// Cancellation Types
pub mod cancellation_type {
    pub const MME_UPDATE_PROCEDURE: u32 = 0;
    pub const SGSN_UPDATE_PROCEDURE: u32 = 1;
    pub const SUBSCRIPTION_WITHDRAWAL: u32 = 2;
    pub const UPDATE_PROCEDURE_IWF: u32 = 3;
    pub const INITIAL_ATTACH_PROCEDURE: u32 = 4;
}

// ============================================================================
// Diameter Message Structures
// ============================================================================

/// E-UTRAN Authentication Vector
#[derive(Debug, Clone, Default)]
pub struct EUtranVector {
    /// Random challenge
    pub rand: [u8; 16],
    /// Expected response
    pub xres: Vec<u8>,
    /// Authentication token
    pub autn: [u8; 16],
    /// Key for ASME
    pub kasme: [u8; 32],
}

/// Authentication Information Answer message
#[derive(Debug, Clone, Default)]
pub struct AiaMessage {
    /// Result code
    pub result_code: u32,
    /// Experimental result code (if any)
    pub experimental_result_code: Option<u32>,
    /// E-UTRAN vector
    pub e_utran_vector: EUtranVector,
}

/// Subscription Data
#[derive(Debug, Clone, Default)]
pub struct SubscriptionData {
    /// MSISDN
    pub msisdn: Vec<u8>,
    /// A-MSISDN
    pub a_msisdn: Vec<u8>,
    /// Network access mode
    pub network_access_mode: u32,
    /// Subscribed RAU/TAU timer
    pub subscribed_rau_tau_timer: u32,
    /// AMBR uplink (bps)
    pub ambr_uplink: u64,
    /// AMBR downlink (bps)
    pub ambr_downlink: u64,
    /// Context identifier
    pub context_identifier: u32,
    /// APN configurations
    pub apn_configs: Vec<ApnConfiguration>,
    /// Charging characteristics
    pub charging_characteristics: Option<[u8; 2]>,
}

/// APN Configuration
#[derive(Debug, Clone, Default)]
pub struct ApnConfiguration {
    /// Context identifier
    pub context_identifier: u32,
    /// Service selection (APN name)
    pub service_selection: String,
    /// PDN type (1=IPv4, 2=IPv6, 3=IPv4v6)
    pub pdn_type: u8,
    /// QoS class identifier
    pub qci: u8,
    /// ARP priority level
    pub arp_priority_level: u8,
    /// ARP pre-emption capability
    pub arp_pre_emption_capability: bool,
    /// ARP pre-emption vulnerability
    pub arp_pre_emption_vulnerability: bool,
    /// AMBR uplink (bps)
    pub ambr_uplink: u64,
    /// AMBR downlink (bps)
    pub ambr_downlink: u64,
    /// Charging characteristics
    pub charging_characteristics: Option<[u8; 2]>,
}

/// Update Location Answer message
#[derive(Debug, Clone, Default)]
pub struct UlaMessage {
    /// Result code
    pub result_code: u32,
    /// Experimental result code (if any)
    pub experimental_result_code: Option<u32>,
    /// ULA flags
    pub ula_flags: u32,
    /// Subscription data
    pub subscription_data: SubscriptionData,
}

/// Cancel Location Request message
#[derive(Debug, Clone, Default)]
pub struct ClrMessage {
    /// Cancellation type
    pub cancellation_type: u32,
    /// CLR flags
    pub clr_flags: u32,
}

/// Insert Subscriber Data Request message
#[derive(Debug, Clone, Default)]
pub struct IdrMessage {
    /// IDR flags
    pub idr_flags: u32,
    /// Subscription data
    pub subscription_data: SubscriptionData,
}

/// S6a Message wrapper
#[derive(Debug, Clone)]
pub enum S6aMessage {
    /// Authentication Information Answer
    Aia(AiaMessage),
    /// Update Location Answer
    Ula(UlaMessage),
    /// Cancel Location Request
    Clr(ClrMessage),
    /// Insert Subscriber Data Request
    Idr(IdrMessage),
    /// Purge UE Answer
    Pua { result_code: u32, pua_flags: u32 },
}

// ============================================================================
// Result Types
// ============================================================================

/// Diameter path operation result
pub type DiameterResult<T> = Result<T, DiameterError>;

/// Diameter path error types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiameterError {
    /// Not initialized
    NotInitialized,
    /// Connection failed
    ConnectionFailed,
    /// Message build failed
    BuildFailed,
    /// Send failed
    SendFailed,
    /// Timeout
    Timeout,
    /// Invalid response
    InvalidResponse,
    /// HSS error
    HssError(u32),
}

impl std::fmt::Display for DiameterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DiameterError::NotInitialized => write!(f, "Diameter not initialized"),
            DiameterError::ConnectionFailed => write!(f, "Diameter connection failed"),
            DiameterError::BuildFailed => write!(f, "Message build failed"),
            DiameterError::SendFailed => write!(f, "Send failed"),
            DiameterError::Timeout => write!(f, "Timeout"),
            DiameterError::InvalidResponse => write!(f, "Invalid response"),
            DiameterError::HssError(code) => write!(f, "HSS error: {code}"),
        }
    }
}

impl std::error::Error for DiameterError {}

// ============================================================================
// Session State
// ============================================================================

/// Diameter session state
#[derive(Debug, Clone, Default)]
pub struct SessionState {
    /// MME UE ID
    pub mme_ue_id: u64,
    /// eNB UE ID
    pub enb_ue_id: u64,
    /// Timestamp
    pub timestamp: u64,
    /// GTP transaction ID (for Gn interface)
    pub gtp_xact_id: Option<u64>,
}

// ============================================================================
// Diameter Path Functions
// ============================================================================

/// Initialize Diameter S6a interface
pub fn mme_fd_init() -> DiameterResult<()> {
    log::info!("Initializing Diameter S6a interface");
    // In actual implementation, this would initialize freeDiameter
    Ok(())
}

/// Finalize Diameter S6a interface
pub fn mme_fd_final() {
    log::info!("Finalizing Diameter S6a interface");
    // In actual implementation, this would cleanup freeDiameter
}

/// Send Authentication Information Request
///
/// # Arguments
/// * `mme_ue` - MME UE context
/// * `resync` - Whether this is a re-sync request
///
/// # Returns
/// * `Ok(())` - Request sent successfully
/// * `Err(DiameterError)` - On error
pub fn mme_s6a_send_air(
    mme_ue: &MmeUe,
    resync: bool,
) -> DiameterResult<()> {
    if mme_ue.imsi_bcd.is_empty() {
        log::error!("No IMSI for AIR");
        return Err(DiameterError::BuildFailed);
    }

    log::debug!(
        "[{}] Sending Authentication-Information-Request (resync={})",
        mme_ue.imsi_bcd,
        resync
    );

    // In actual implementation:
    // 1. Create AIR message
    // 2. Add User-Name AVP (IMSI)
    // 3. Add Visited-PLMN-Id AVP
    // 4. Add Requested-EUTRAN-Authentication-Info AVP
    // 5. If resync, add Re-Synchronization-Info AVP
    // 6. Send message

    Ok(())
}

/// Send Update Location Request
///
/// # Arguments
/// * `mme_ue` - MME UE context
/// * `initial_attach` - Whether this is initial attach
///
/// # Returns
/// * `Ok(())` - Request sent successfully
/// * `Err(DiameterError)` - On error
pub fn mme_s6a_send_ulr(
    mme_ue: &MmeUe,
    initial_attach: bool,
) -> DiameterResult<()> {
    if mme_ue.imsi_bcd.is_empty() {
        log::error!("No IMSI for ULR");
        return Err(DiameterError::BuildFailed);
    }

    log::debug!(
        "[{}] Sending Update-Location-Request (initial_attach={})",
        mme_ue.imsi_bcd,
        initial_attach
    );

    // In actual implementation:
    // 1. Create ULR message
    // 2. Add User-Name AVP (IMSI)
    // 3. Add Visited-PLMN-Id AVP
    // 4. Add RAT-Type AVP
    // 5. Add ULR-Flags AVP
    // 6. Send message

    Ok(())
}

/// Send Purge UE Request
///
/// # Arguments
/// * `mme_ue` - MME UE context
///
/// # Returns
/// * `Ok(())` - Request sent successfully
/// * `Err(DiameterError)` - On error
pub fn mme_s6a_send_pur(mme_ue: &MmeUe) -> DiameterResult<()> {
    if mme_ue.imsi_bcd.is_empty() {
        log::error!("No IMSI for PUR");
        return Err(DiameterError::BuildFailed);
    }

    log::debug!("[{}] Sending Purge-UE-Request", mme_ue.imsi_bcd);

    // In actual implementation:
    // 1. Create PUR message
    // 2. Add User-Name AVP (IMSI)
    // 3. Send message

    Ok(())
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Convert Diameter result code to EMM cause
pub fn emm_cause_from_diameter(
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

/// Encode PLMN ID for Diameter
pub fn encode_visited_plmn_id(mcc: &str, mnc: &str) -> Vec<u8> {
    let mut plmn = vec![0u8; 3];
    
    let mcc_digits: Vec<u8> = mcc.chars()
        .filter_map(|c| c.to_digit(10).map(|d| d as u8))
        .collect();
    let mnc_digits: Vec<u8> = mnc.chars()
        .filter_map(|c| c.to_digit(10).map(|d| d as u8))
        .collect();
    
    if mcc_digits.len() >= 3 {
        plmn[0] = (mcc_digits[1] << 4) | mcc_digits[0];
        if mnc_digits.len() == 2 {
            plmn[1] = 0xf0 | mcc_digits[2];
            plmn[2] = (mnc_digits[1] << 4) | mnc_digits[0];
        } else if mnc_digits.len() >= 3 {
            plmn[1] = (mnc_digits[2] << 4) | mcc_digits[2];
            plmn[2] = (mnc_digits[1] << 4) | mnc_digits[0];
        }
    }
    
    plmn
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_diameter_error_display() {
        assert_eq!(
            format!("{}", DiameterError::NotInitialized),
            "Diameter not initialized"
        );
        assert_eq!(
            format!("{}", DiameterError::HssError(5001)),
            "HSS error: 5001"
        );
    }

    #[test]
    fn test_emm_cause_from_diameter_success() {
        let cause = emm_cause_from_diameter(
            Some(result_code::DIAMETER_SUCCESS),
            None,
        );
        assert_eq!(cause, EmmCause::RequestAccepted);
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
    fn test_emm_cause_from_diameter_roaming_not_allowed() {
        let cause = emm_cause_from_diameter(
            None,
            Some(experimental_result::DIAMETER_ERROR_ROAMING_NOT_ALLOWED),
        );
        assert_eq!(cause, EmmCause::RoamingNotAllowedInTa);
    }

    #[test]
    fn test_encode_visited_plmn_id_3digit_mnc() {
        let plmn = encode_visited_plmn_id("310", "410");
        assert_eq!(plmn.len(), 3);
    }

    #[test]
    fn test_encode_visited_plmn_id_2digit_mnc() {
        let plmn = encode_visited_plmn_id("310", "26");
        assert_eq!(plmn.len(), 3);
        // MNC filler should be 0xf
        assert_eq!(plmn[1] & 0xf0, 0xf0);
    }

    #[test]
    fn test_session_state_default() {
        let state = SessionState::default();
        assert_eq!(state.mme_ue_id, 0);
        assert_eq!(state.enb_ue_id, 0);
        assert!(state.gtp_xact_id.is_none());
    }

    #[test]
    fn test_e_utran_vector_default() {
        let vector = EUtranVector::default();
        assert_eq!(vector.rand, [0u8; 16]);
        assert_eq!(vector.autn, [0u8; 16]);
        assert_eq!(vector.kasme, [0u8; 32]);
        assert!(vector.xres.is_empty());
    }

    #[test]
    fn test_aia_message_default() {
        let msg = AiaMessage::default();
        assert_eq!(msg.result_code, 0);
        assert!(msg.experimental_result_code.is_none());
    }

    #[test]
    fn test_subscription_data_default() {
        let data = SubscriptionData::default();
        assert!(data.msisdn.is_empty());
        assert!(data.apn_configs.is_empty());
        assert_eq!(data.network_access_mode, 0);
    }
}
