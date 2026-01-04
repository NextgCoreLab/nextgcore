//! S6a Interface - MME <-> HSS (3GPP TS 29.272)
//!
//! The S6a interface is used between the MME and HSS for:
//! - Authentication Information Retrieval (AIR/AIA)
//! - Update Location (ULR/ULA)
//! - Purge UE (PUR/PUA)
//! - Cancel Location (CLR/CLA)
//! - Insert Subscriber Data (IDR/IDA)

use bytes::Bytes;

use crate::avp::{Avp, AvpData};
use crate::common::avp_code;
use crate::error::DiameterResult;
use crate::message::DiameterMessage;
use crate::OGS_3GPP_VENDOR_ID;

/// S6a Application ID (3GPP TS 29.272)
pub const S6A_APPLICATION_ID: u32 = 16777251;

/// S6a Command Codes
pub mod cmd {
    /// Update-Location-Request/Answer
    pub const UPDATE_LOCATION: u32 = 316;
    /// Cancel-Location-Request/Answer
    pub const CANCEL_LOCATION: u32 = 317;
    /// Authentication-Information-Request/Answer
    pub const AUTHENTICATION_INFORMATION: u32 = 318;
    /// Insert-Subscriber-Data-Request/Answer
    pub const INSERT_SUBSCRIBER_DATA: u32 = 319;
    /// Purge-UE-Request/Answer
    pub const PURGE_UE: u32 = 321;
}

/// S6a AVP Codes (3GPP specific)
pub mod avp {
    /// Context-Identifier
    pub const CONTEXT_IDENTIFIER: u32 = 1423;
    /// All-APN-Configurations-Included-Indicator
    pub const ALL_APN_CONFIG_INC_IND: u32 = 1428;
    /// APN-Configuration
    pub const APN_CONFIGURATION: u32 = 1430;
    /// ULR-Flags
    pub const ULR_FLAGS: u32 = 1405;
    /// ULA-Flags
    pub const ULA_FLAGS: u32 = 1406;
    /// Visited-PLMN-Id
    pub const VISITED_PLMN_ID: u32 = 1407;
    /// Requested-EUTRAN-Authentication-Info
    pub const REQ_EUTRAN_AUTH_INFO: u32 = 1408;
    /// Number-Of-Requested-Vectors
    pub const NUM_REQUESTED_VECTORS: u32 = 1410;
    /// Immediate-Response-Preferred
    pub const IMMEDIATE_RESPONSE_PREFERRED: u32 = 1412;
    /// Re-Synchronization-Info
    pub const RE_SYNC_INFO: u32 = 1411;
    /// Authentication-Info
    pub const AUTHENTICATION_INFO: u32 = 1413;
    /// E-UTRAN-Vector
    pub const E_UTRAN_VECTOR: u32 = 1414;
    /// RAND
    pub const RAND: u32 = 1447;
    /// XRES
    pub const XRES: u32 = 1448;
    /// AUTN
    pub const AUTN: u32 = 1449;
    /// KASME
    pub const KASME: u32 = 1450;
    /// Subscription-Data
    pub const SUBSCRIPTION_DATA: u32 = 1400;
    /// Subscriber-Status
    pub const SUBSCRIBER_STATUS: u32 = 1424;
    /// MSISDN
    pub const MSISDN: u32 = 701;
    /// A-MSISDN
    pub const A_MSISDN: u32 = 1643;
    /// Network-Access-Mode
    pub const NETWORK_ACCESS_MODE: u32 = 1417;
    /// Operator-Determined-Barring
    pub const OPERATOR_DETERMINED_BARRING: u32 = 1425;
    /// Access-Restriction-Data
    pub const ACCESS_RESTRICTION_DATA: u32 = 1426;
    /// APN-Configuration-Profile
    pub const APN_CONFIGURATION_PROFILE: u32 = 1429;
    /// Subscribed-Periodic-RAU-TAU-Timer
    pub const SUBSCRIBED_RAU_TAU_TIMER: u32 = 1619;
    /// AMBR
    pub const AMBR: u32 = 1435;
    /// Max-Requested-Bandwidth-UL
    pub const MAX_BANDWIDTH_UL: u32 = 516;
    /// Max-Requested-Bandwidth-DL
    pub const MAX_BANDWIDTH_DL: u32 = 515;
    /// PDN-Type
    pub const PDN_TYPE: u32 = 1456;
    /// EPS-Subscribed-QoS-Profile
    pub const EPS_SUBSCRIBED_QOS_PROFILE: u32 = 1431;
    /// QoS-Class-Identifier
    pub const QOS_CLASS_IDENTIFIER: u32 = 1028;
    /// Allocation-Retention-Priority
    pub const ALLOCATION_RETENTION_PRIORITY: u32 = 1034;
    /// Priority-Level
    pub const PRIORITY_LEVEL: u32 = 1046;
    /// Pre-emption-Capability
    pub const PRE_EMPTION_CAPABILITY: u32 = 1047;
    /// Pre-emption-Vulnerability
    pub const PRE_EMPTION_VULNERABILITY: u32 = 1048;
    /// Served-Party-IP-Address
    pub const SERVED_PARTY_IP_ADDRESS: u32 = 848;
    /// PDN-GW-Allocation-Type
    pub const PDN_GW_ALLOCATION_TYPE: u32 = 1438;
    /// VPLMN-Dynamic-Address-Allowed
    pub const VPLMN_DYNAMIC_ADDRESS_ALLOWED: u32 = 1432;
    /// Cancellation-Type
    pub const CANCELLATION_TYPE: u32 = 1420;
    /// CLR-Flags
    pub const CLR_FLAGS: u32 = 1638;
    /// IDR-Flags
    pub const IDR_FLAGS: u32 = 1490;
    /// PUA-Flags
    pub const PUA_FLAGS: u32 = 1442;
    /// Terminal-Information
    pub const TERMINAL_INFORMATION: u32 = 1401;
    /// IMEI
    pub const IMEI: u32 = 1402;
    /// Software-Version
    pub const SOFTWARE_VERSION: u32 = 1403;
    /// UE-SRVCC-Capability
    pub const UE_SRVCC_CAPABILITY: u32 = 1615;
    /// Supported-Features
    pub const SUPPORTED_FEATURES: u32 = 628;
    /// Feature-List-ID
    pub const FEATURE_LIST_ID: u32 = 629;
    /// Feature-List
    pub const FEATURE_LIST: u32 = 630;
    /// 3GPP-Charging-Characteristics
    pub const CHARGING_CHARACTERISTICS: u32 = 13;
}


/// ULR Flags
pub mod ulr_flags {
    /// Single-Registration-Indication
    pub const SINGLE_REGISTRATION_IND: u32 = 1;
    /// S6a/S6d-Indicator
    pub const S6A_S6D_INDICATOR: u32 = 1 << 1;
    /// Skip-Subscriber-Data
    pub const SKIP_SUBSCRIBER_DATA: u32 = 1 << 2;
    /// GPRS-Subscription-Data-Indicator
    pub const GPRS_SUBSCRIPTION_DATA_IND: u32 = 1 << 3;
    /// Node-Type-Indicator
    pub const NODE_TYPE_IND: u32 = 1 << 4;
    /// Initial-Attach-Indicator
    pub const INITIAL_ATTACH_IND: u32 = 1 << 5;
    /// PS-LCS-Supported-By-UE
    pub const PS_LCS_SUPPORTED_BY_UE: u32 = 1 << 6;
}

/// ULA Flags
pub mod ula_flags {
    /// Separation-Indication
    pub const SEPARATION_INDICATION: u32 = 0;
    /// MME-Registered-for-SMS
    pub const MME_REGISTERED_FOR_SMS: u32 = 1;
}

/// CLR Flags
pub mod clr_flags {
    /// S6a/S6d-Indicator
    pub const S6A_S6D_INDICATOR: u32 = 1;
    /// Reattach-Required
    pub const REATTACH_REQUIRED: u32 = 1 << 1;
}

/// IDR Flags
pub mod idr_flags {
    /// UE-Reachability-Request
    pub const UE_REACHABILITY: u32 = 1;
    /// T-ADS-Data-Request
    pub const TADS_DATA: u32 = 1 << 1;
    /// EPS-User-State-Request
    pub const EPS_USER_STATE: u32 = 1 << 2;
    /// EPS-Location-Information-Request
    pub const EPS_LOCATION_INFO: u32 = 1 << 3;
    /// Current-Location-Request
    pub const CURRENT_LOCATION: u32 = 1 << 4;
    /// Local-Time-Zone-Request
    pub const LOCAL_TZ: u32 = 1 << 5;
    /// Remove-SMS-Registration
    pub const REMOVE_SMS_REG: u32 = 1 << 6;
    /// RAT-Type-Requested
    pub const RAT_TYPE: u32 = 1 << 7;
    /// P-CSCF-Restoration-Request
    pub const PCSCF_RESTORATION: u32 = 1 << 8;
}

/// PUA Flags
pub mod pua_flags {
    /// Freeze-M-TMSI
    pub const FREEZE_MTMSI: u32 = 1;
    /// Freeze-P-TMSI
    pub const FREEZE_PTMSI: u32 = 1 << 1;
}

/// Cancellation Type values
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum CancellationType {
    MmeUpdateProcedure = 0,
    SgsnUpdateProcedure = 1,
    SubscriptionWithdrawal = 2,
    UpdateProcedureIwf = 3,
    InitialAttachProcedure = 4,
}

/// UE SRVCC Capability
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum UeSrvccCapability {
    NotSupported = 0,
    Supported = 1,
}

/// PDN GW Allocation Type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum PdnGwAllocationType {
    Static = 0,
    Dynamic = 1,
}

/// VPLMN Dynamic Address Allowed
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum VplmnDynamicAddressAllowed {
    NotAllowed = 0,
    Allowed = 1,
}

/// S6a Experimental Result Codes
pub mod exp_result {
    /// Authentication-Data-Unavailable
    pub const AUTHENTICATION_DATA_UNAVAILABLE: u32 = 4181;
    /// Error-User-Unknown
    pub const ERROR_USER_UNKNOWN: u32 = 5001;
    /// Error-Roaming-Not-Allowed
    pub const ERROR_ROAMING_NOT_ALLOWED: u32 = 5004;
    /// Error-Unknown-EPS-Subscription
    pub const ERROR_UNKNOWN_EPS_SUBSCRIPTION: u32 = 5420;
    /// Error-RAT-Not-Allowed
    pub const ERROR_RAT_NOT_ALLOWED: u32 = 5421;
    /// Error-Equipment-Unknown
    pub const ERROR_EQUIPMENT_UNKNOWN: u32 = 5422;
    /// Error-Unknown-Serving-Node
    pub const ERROR_UNKNOWN_SERVING_NODE: u32 = 5423;
}

/// E-UTRAN authentication vector
#[derive(Debug, Clone)]
pub struct EUtranVector {
    /// RAND (16 bytes)
    pub rand: [u8; 16],
    /// XRES (variable length, max 16 bytes)
    pub xres: Vec<u8>,
    /// AUTN (16 bytes)
    pub autn: [u8; 16],
    /// KASME (32 bytes)
    pub kasme: [u8; 32],
}

impl Default for EUtranVector {
    fn default() -> Self {
        Self {
            rand: [0u8; 16],
            xres: Vec::new(),
            autn: [0u8; 16],
            kasme: [0u8; 32],
        }
    }
}

/// AIA (Authentication-Information-Answer) message data
#[derive(Debug, Clone, Default)]
pub struct AiaMessage {
    /// E-UTRAN authentication vector
    pub e_utran_vector: EUtranVector,
}

/// ULA (Update-Location-Answer) message data
#[derive(Debug, Clone, Default)]
pub struct UlaMessage {
    /// ULA flags
    pub ula_flags: u32,
    // Note: subscription_data would be a complex type from ogs-core
}

/// PUA (Purge-UE-Answer) message data
#[derive(Debug, Clone, Default)]
pub struct PuaMessage {
    /// PUA flags
    pub pua_flags: u32,
}

/// CLR (Cancel-Location-Request) message data
#[derive(Debug, Clone, Default)]
pub struct ClrMessage {
    /// CLR flags
    pub clr_flags: u32,
    /// Cancellation type
    pub cancellation_type: u32,
}

/// IDR (Insert-Subscriber-Data-Request) message data
#[derive(Debug, Clone, Default)]
pub struct IdrMessage {
    /// IDR flags
    pub idr_flags: u32,
    /// Subscription data mask
    pub subdatamask: u32,
    // Note: subscription_data would be a complex type from ogs-core
}

/// S6a message container
#[derive(Debug, Clone)]
pub enum S6aMessageData {
    /// Authentication-Information-Answer
    Aia(AiaMessage),
    /// Update-Location-Answer
    Ula(UlaMessage),
    /// Purge-UE-Answer
    Pua(PuaMessage),
    /// Cancel-Location-Request
    Clr(ClrMessage),
    /// Insert-Subscriber-Data-Request
    Idr(IdrMessage),
}

/// S6a message
#[derive(Debug, Clone)]
pub struct S6aMessage {
    /// Command code
    pub cmd_code: u16,
    /// Result code
    pub result_code: u32,
    /// Error pointer (for compatibility)
    pub err: Option<u32>,
    /// Experimental error pointer (for compatibility)
    pub exp_err: Option<u32>,
    /// Message-specific data
    pub data: Option<S6aMessageData>,
}

impl S6aMessage {
    /// Create a new S6a message
    pub fn new(cmd_code: u16) -> Self {
        Self {
            cmd_code,
            result_code: 0,
            err: None,
            exp_err: None,
            data: None,
        }
    }
}

/// Create an Authentication-Information-Request (AIR)
pub fn create_air(
    session_id: &str,
    origin_host: &str,
    origin_realm: &str,
    destination_realm: &str,
    user_name: &str,
    visited_plmn_id: &[u8],
    num_vectors: u32,
) -> DiameterMessage {
    let mut msg = DiameterMessage::new_request(cmd::AUTHENTICATION_INFORMATION, S6A_APPLICATION_ID);

    // Session-Id
    msg.add_avp(Avp::mandatory(
        avp_code::SESSION_ID,
        AvpData::Utf8String(session_id.to_string()),
    ));

    // Origin-Host
    msg.add_avp(Avp::mandatory(
        avp_code::ORIGIN_HOST,
        AvpData::DiameterIdentity(origin_host.to_string()),
    ));

    // Origin-Realm
    msg.add_avp(Avp::mandatory(
        avp_code::ORIGIN_REALM,
        AvpData::DiameterIdentity(origin_realm.to_string()),
    ));

    // Destination-Realm
    msg.add_avp(Avp::mandatory(
        avp_code::DESTINATION_REALM,
        AvpData::DiameterIdentity(destination_realm.to_string()),
    ));

    // User-Name (IMSI)
    msg.add_avp(Avp::mandatory(
        avp_code::USER_NAME,
        AvpData::Utf8String(user_name.to_string()),
    ));

    // Auth-Session-State (NO_STATE_MAINTAINED)
    msg.add_avp(Avp::mandatory(
        avp_code::AUTH_SESSION_STATE,
        AvpData::Enumerated(1),
    ));

    // Visited-PLMN-Id
    msg.add_avp(Avp::vendor_mandatory(
        avp::VISITED_PLMN_ID,
        OGS_3GPP_VENDOR_ID,
        AvpData::OctetString(Bytes::copy_from_slice(visited_plmn_id)),
    ));

    // Requested-EUTRAN-Authentication-Info (grouped)
    let req_auth_info = Avp::vendor_mandatory(
        avp::REQ_EUTRAN_AUTH_INFO,
        OGS_3GPP_VENDOR_ID,
        AvpData::Grouped(vec![Avp::vendor_mandatory(
            avp::NUM_REQUESTED_VECTORS,
            OGS_3GPP_VENDOR_ID,
            AvpData::Unsigned32(num_vectors),
        )]),
    );
    msg.add_avp(req_auth_info);

    msg
}

/// Create an Update-Location-Request (ULR)
pub fn create_ulr(
    session_id: &str,
    origin_host: &str,
    origin_realm: &str,
    destination_realm: &str,
    user_name: &str,
    visited_plmn_id: &[u8],
    ulr_flags: u32,
    rat_type: u32,
) -> DiameterMessage {
    let mut msg = DiameterMessage::new_request(cmd::UPDATE_LOCATION, S6A_APPLICATION_ID);

    // Session-Id
    msg.add_avp(Avp::mandatory(
        avp_code::SESSION_ID,
        AvpData::Utf8String(session_id.to_string()),
    ));

    // Origin-Host
    msg.add_avp(Avp::mandatory(
        avp_code::ORIGIN_HOST,
        AvpData::DiameterIdentity(origin_host.to_string()),
    ));

    // Origin-Realm
    msg.add_avp(Avp::mandatory(
        avp_code::ORIGIN_REALM,
        AvpData::DiameterIdentity(origin_realm.to_string()),
    ));

    // Destination-Realm
    msg.add_avp(Avp::mandatory(
        avp_code::DESTINATION_REALM,
        AvpData::DiameterIdentity(destination_realm.to_string()),
    ));

    // User-Name (IMSI)
    msg.add_avp(Avp::mandatory(
        avp_code::USER_NAME,
        AvpData::Utf8String(user_name.to_string()),
    ));

    // Auth-Session-State (NO_STATE_MAINTAINED)
    msg.add_avp(Avp::mandatory(
        avp_code::AUTH_SESSION_STATE,
        AvpData::Enumerated(1),
    ));

    // RAT-Type
    msg.add_avp(Avp::vendor_mandatory(
        avp_code::RAT_TYPE,
        OGS_3GPP_VENDOR_ID,
        AvpData::Enumerated(rat_type as i32),
    ));

    // ULR-Flags
    msg.add_avp(Avp::vendor_mandatory(
        avp::ULR_FLAGS,
        OGS_3GPP_VENDOR_ID,
        AvpData::Unsigned32(ulr_flags),
    ));

    // Visited-PLMN-Id
    msg.add_avp(Avp::vendor_mandatory(
        avp::VISITED_PLMN_ID,
        OGS_3GPP_VENDOR_ID,
        AvpData::OctetString(Bytes::copy_from_slice(visited_plmn_id)),
    ));

    msg
}

/// Parse E-UTRAN vector from grouped AVP
pub fn parse_e_utran_vector(avp: &Avp) -> DiameterResult<EUtranVector> {
    let mut vector = EUtranVector::default();

    if let Some(grouped) = avp.as_grouped() {
        for inner in grouped {
            match inner.code {
                avp::RAND => {
                    if let Some(data) = inner.as_octet_string() {
                        if data.len() >= 16 {
                            vector.rand.copy_from_slice(&data[..16]);
                        }
                    }
                }
                avp::XRES => {
                    if let Some(data) = inner.as_octet_string() {
                        vector.xres = data.to_vec();
                    }
                }
                avp::AUTN => {
                    if let Some(data) = inner.as_octet_string() {
                        if data.len() >= 16 {
                            vector.autn.copy_from_slice(&data[..16]);
                        }
                    }
                }
                avp::KASME => {
                    if let Some(data) = inner.as_octet_string() {
                        if data.len() >= 32 {
                            vector.kasme.copy_from_slice(&data[..32]);
                        }
                    }
                }
                _ => {}
            }
        }
    }

    Ok(vector)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_air() {
        let msg = create_air(
            "session123",
            "mme.epc.mnc001.mcc001.3gppnetwork.org",
            "epc.mnc001.mcc001.3gppnetwork.org",
            "epc.mnc001.mcc001.3gppnetwork.org",
            "001010123456789",
            &[0x00, 0x01, 0x01],
            1,
        );

        assert_eq!(msg.header.command_code, cmd::AUTHENTICATION_INFORMATION);
        assert_eq!(msg.header.application_id, S6A_APPLICATION_ID);
        assert!(msg.header.is_request());
    }

    #[test]
    fn test_create_ulr() {
        let msg = create_ulr(
            "session123",
            "mme.epc.mnc001.mcc001.3gppnetwork.org",
            "epc.mnc001.mcc001.3gppnetwork.org",
            "epc.mnc001.mcc001.3gppnetwork.org",
            "001010123456789",
            &[0x00, 0x01, 0x01],
            ulr_flags::S6A_S6D_INDICATOR | ulr_flags::INITIAL_ATTACH_IND,
            1004, // E-UTRAN
        );

        assert_eq!(msg.header.command_code, cmd::UPDATE_LOCATION);
        assert_eq!(msg.header.application_id, S6A_APPLICATION_ID);
    }
}
