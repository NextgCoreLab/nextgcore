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
use crate::NEXTGCORE_3GPP_VENDOR_ID;

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
    /// PUR-Flags
    pub const PUR_FLAGS: u32 = 1635;
    /// Item-Number (3GPP TS 29.272, orders E-UTRAN-Vectors)
    pub const ITEM_NUMBER: u32 = 1419;
    /// Service-Selection (RFC 5778, no vendor)
    pub const SERVICE_SELECTION: u32 = 493;
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

/// PUR Flags (TS 29.272 7.3.149)
pub mod pur_flags {
    /// UE-Purged-In-MME
    pub const UE_PURGED_IN_MME: u32 = 1;
    /// UE-Purged-In-SGSN
    pub const UE_PURGED_IN_SGSN: u32 = 1 << 1;
}

/// PDN-Type values (TS 29.272 7.3.62)
pub mod pdn_type {
    /// IPv4 only
    pub const IPV4: u32 = 0;
    /// IPv6 only
    pub const IPV6: u32 = 1;
    /// IPv4v6 dual-stack
    pub const IPV4V6: u32 = 2;
    /// IPv4 or IPv6
    pub const IPV4_OR_IPV6: u32 = 3;
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
#[derive(Debug, Clone, Default)]
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
    // Note: subscription_data would be a complex type from nextgcore-core
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
    // Note: subscription_data would be a complex type from nextgcore-core
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
        NEXTGCORE_3GPP_VENDOR_ID,
        AvpData::OctetString(Bytes::copy_from_slice(visited_plmn_id)),
    ));

    // Requested-EUTRAN-Authentication-Info (grouped)
    let req_auth_info = Avp::vendor_mandatory(
        avp::REQ_EUTRAN_AUTH_INFO,
        NEXTGCORE_3GPP_VENDOR_ID,
        AvpData::Grouped(vec![Avp::vendor_mandatory(
            avp::NUM_REQUESTED_VECTORS,
            NEXTGCORE_3GPP_VENDOR_ID,
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
        NEXTGCORE_3GPP_VENDOR_ID,
        AvpData::Enumerated(rat_type as i32),
    ));

    // ULR-Flags
    msg.add_avp(Avp::vendor_mandatory(
        avp::ULR_FLAGS,
        NEXTGCORE_3GPP_VENDOR_ID,
        AvpData::Unsigned32(ulr_flags),
    ));

    // Visited-PLMN-Id
    msg.add_avp(Avp::vendor_mandatory(
        avp::VISITED_PLMN_ID,
        NEXTGCORE_3GPP_VENDOR_ID,
        AvpData::OctetString(Bytes::copy_from_slice(visited_plmn_id)),
    ));

    msg
}

/// Parse E-UTRAN vector from grouped AVP.
///
/// Works on both in-memory grouped AVPs and wire-decoded AVPs (raw payload).
pub fn parse_e_utran_vector(avp: &Avp) -> DiameterResult<EUtranVector> {
    let mut vector = EUtranVector::default();

    if let Ok(grouped) = avp.parse_grouped() {
        for inner in &grouped {
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

/// Build an E-UTRAN-Vector grouped AVP from an authentication vector.
///
/// Per TS 29.272 7.3.18: Item-Number is included when more than one vector
/// is carried so the MME can order them.
pub fn build_e_utran_vector_avp(item_number: Option<u32>, v: &EUtranVector) -> Avp {
    let mut group = Vec::with_capacity(5);
    if let Some(n) = item_number {
        group.push(Avp::vendor_mandatory(
            avp::ITEM_NUMBER,
            NEXTGCORE_3GPP_VENDOR_ID,
            AvpData::Unsigned32(n),
        ));
    }
    group.push(Avp::vendor_mandatory(
        avp::RAND,
        NEXTGCORE_3GPP_VENDOR_ID,
        AvpData::OctetString(Bytes::copy_from_slice(&v.rand)),
    ));
    group.push(Avp::vendor_mandatory(
        avp::XRES,
        NEXTGCORE_3GPP_VENDOR_ID,
        AvpData::OctetString(Bytes::copy_from_slice(&v.xres)),
    ));
    group.push(Avp::vendor_mandatory(
        avp::AUTN,
        NEXTGCORE_3GPP_VENDOR_ID,
        AvpData::OctetString(Bytes::copy_from_slice(&v.autn)),
    ));
    group.push(Avp::vendor_mandatory(
        avp::KASME,
        NEXTGCORE_3GPP_VENDOR_ID,
        AvpData::OctetString(Bytes::copy_from_slice(&v.kasme)),
    ));
    Avp::vendor_mandatory(
        avp::E_UTRAN_VECTOR,
        NEXTGCORE_3GPP_VENDOR_ID,
        AvpData::Grouped(group),
    )
}

/// Parse all E-UTRAN-Vectors from the Authentication-Info AVP of an AIA.
pub fn parse_authentication_info(msg: &DiameterMessage) -> Vec<EUtranVector> {
    let mut vectors = Vec::new();
    if let Some(auth_info) = msg.find_avp(avp::AUTHENTICATION_INFO) {
        if let Ok(group) = auth_info.parse_grouped() {
            for inner in &group {
                if inner.code == avp::E_UTRAN_VECTOR {
                    if let Ok(v) = parse_e_utran_vector(inner) {
                        vectors.push(v);
                    }
                }
            }
        }
    }
    vectors
}

// ============================================================================
// Re-Synchronization-Info helpers (TS 29.272 7.3.15)
// ============================================================================

/// Insert Re-Synchronization-Info (RAND || AUTS, 30 octets) inside the
/// Requested-EUTRAN-Authentication-Info grouped AVP of an AIR.
///
/// Per TS 29.272 7.3.11, Re-Synchronization-Info is a member of
/// Requested-EUTRAN-Authentication-Info, NOT a top-level AVP.
///
/// Returns `false` if the AIR has no Requested-EUTRAN-Authentication-Info AVP.
pub fn add_resync_info(msg: &mut DiameterMessage, rand: &[u8; 16], auts: &[u8; 14]) -> bool {
    let Some(req) = msg
        .avps
        .iter_mut()
        .find(|a| a.code == avp::REQ_EUTRAN_AUTH_INFO)
    else {
        return false;
    };
    let Ok(mut group) = req.parse_grouped() else {
        return false;
    };
    let mut payload = Vec::with_capacity(30);
    payload.extend_from_slice(rand);
    payload.extend_from_slice(auts);
    group.push(Avp::vendor_mandatory(
        avp::RE_SYNC_INFO,
        NEXTGCORE_3GPP_VENDOR_ID,
        AvpData::OctetString(Bytes::from(payload)),
    ));
    req.data = AvpData::Grouped(group);
    true
}

/// Extract Re-Synchronization-Info (RAND, AUTS) from inside the
/// Requested-EUTRAN-Authentication-Info grouped AVP of an AIR.
pub fn find_resync_info(msg: &DiameterMessage) -> Option<([u8; 16], [u8; 14])> {
    let req = msg.find_avp(avp::REQ_EUTRAN_AUTH_INFO)?;
    let group = req.parse_grouped().ok()?;
    let resync = crate::avp::find_avp(&group, avp::RE_SYNC_INFO)?;
    let data = resync.as_octet_string()?;
    if data.len() != 30 {
        return None;
    }
    let mut rand = [0u8; 16];
    let mut auts = [0u8; 14];
    rand.copy_from_slice(&data[..16]);
    auts.copy_from_slice(&data[16..30]);
    Some((rand, auts))
}

/// Extract Number-Of-Requested-Vectors from inside
/// Requested-EUTRAN-Authentication-Info (TS 29.272 7.3.14).
pub fn find_num_requested_vectors(msg: &DiameterMessage) -> Option<u32> {
    let req = msg.find_avp(avp::REQ_EUTRAN_AUTH_INFO)?;
    let group = req.parse_grouped().ok()?;
    crate::avp::find_avp(&group, avp::NUM_REQUESTED_VECTORS).and_then(|a| a.as_u32())
}

// ============================================================================
// Experimental-Result helpers (RFC 6733 7.6 / TS 29.272 7.4)
// ============================================================================

/// Build an Experimental-Result grouped AVP carrying a 3GPP result code.
pub fn experimental_result_avp(code: u32) -> Avp {
    Avp::mandatory(
        avp_code::EXPERIMENTAL_RESULT,
        AvpData::Grouped(vec![
            Avp::mandatory(
                avp_code::VENDOR_ID,
                AvpData::Unsigned32(NEXTGCORE_3GPP_VENDOR_ID),
            ),
            Avp::mandatory(
                avp_code::EXPERIMENTAL_RESULT_CODE,
                AvpData::Unsigned32(code),
            ),
        ]),
    )
}

/// Extract the Experimental-Result-Code from a message (works on wire-decoded
/// messages where the grouped payload is raw bytes).
pub fn experimental_result_code(msg: &DiameterMessage) -> Option<u32> {
    let exp = msg.find_avp(avp_code::EXPERIMENTAL_RESULT)?;
    let group = exp.parse_grouped().ok()?;
    crate::avp::find_avp(&group, avp_code::EXPERIMENTAL_RESULT_CODE).and_then(|a| a.as_u32())
}

// ============================================================================
// Subscription-Data (TS 29.272 7.3.2)
// ============================================================================

/// EPS subscription data carried in the ULA/IDR Subscription-Data AVP.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SubscriptionData {
    /// MSISDN (TBCD-encoded)
    pub msisdn: Vec<u8>,
    /// A-MSISDN (TBCD-encoded)
    pub a_msisdn: Vec<u8>,
    /// Subscriber-Status (0 = SERVICE_GRANTED, 1 = OPERATOR_DETERMINED_BARRING)
    pub subscriber_status: u32,
    /// Operator-Determined-Barring bitmask (present when subscriber_status = 1)
    pub operator_determined_barring: Option<u32>,
    /// Access-Restriction-Data bitmask
    pub access_restriction_data: Option<u32>,
    /// Network-Access-Mode (0 = PACKET_AND_CIRCUIT, 2 = ONLY_PACKET)
    pub network_access_mode: u32,
    /// Subscribed-Periodic-RAU-TAU-Timer (seconds)
    pub subscribed_rau_tau_timer: u32,
    /// UE-AMBR uplink (bps)
    pub ambr_uplink: u64,
    /// UE-AMBR downlink (bps)
    pub ambr_downlink: u64,
    /// Default APN Context-Identifier
    pub context_identifier: u32,
    /// All-APN-Configurations-Included-Indicator
    pub all_apn_configs_included: bool,
    /// APN configurations
    pub apn_configs: Vec<ApnConfiguration>,
    /// 3GPP-Charging-Characteristics
    pub charging_characteristics: Option<[u8; 2]>,
}

/// A single APN-Configuration (TS 29.272 7.3.35)
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ApnConfiguration {
    /// Context-Identifier
    pub context_identifier: u32,
    /// Service-Selection (APN name)
    pub service_selection: String,
    /// PDN-Type (Diameter encoding: 0=IPv4, 1=IPv6, 2=IPv4v6, 3=IPv4_OR_IPv6)
    pub pdn_type: u8,
    /// QoS-Class-Identifier
    pub qci: u8,
    /// ARP Priority-Level (1..15)
    pub arp_priority_level: u8,
    /// ARP Pre-emption-Capability (true = PRE-EMPTION_CAPABILITY_ENABLED = 0)
    pub arp_pre_emption_capability: bool,
    /// ARP Pre-emption-Vulnerability (true = PRE-EMPTION_VULNERABILITY_ENABLED = 0)
    pub arp_pre_emption_vulnerability: bool,
    /// APN-AMBR uplink (bps)
    pub ambr_uplink: u64,
    /// APN-AMBR downlink (bps)
    pub ambr_downlink: u64,
    /// 3GPP-Charging-Characteristics
    pub charging_characteristics: Option<[u8; 2]>,
}

/// Build an AMBR grouped AVP (TS 29.272 7.3.41).
///
/// Max-Requested-Bandwidth-UL/DL (TS 29.214 5.3.14/5.3.15) are Unsigned32;
/// rates above u32::MAX are clamped.
pub fn build_ambr_avp(uplink_bps: u64, downlink_bps: u64) -> Avp {
    Avp::vendor_mandatory(
        avp::AMBR,
        NEXTGCORE_3GPP_VENDOR_ID,
        AvpData::Grouped(vec![
            Avp::vendor_mandatory(
                avp::MAX_BANDWIDTH_UL,
                NEXTGCORE_3GPP_VENDOR_ID,
                AvpData::Unsigned32(uplink_bps.min(u32::MAX as u64) as u32),
            ),
            Avp::vendor_mandatory(
                avp::MAX_BANDWIDTH_DL,
                NEXTGCORE_3GPP_VENDOR_ID,
                AvpData::Unsigned32(downlink_bps.min(u32::MAX as u64) as u32),
            ),
        ]),
    )
}

/// Build an EPS-Subscribed-QoS-Profile grouped AVP (TS 29.272 7.3.37).
pub fn build_eps_subscribed_qos_profile_avp(
    qci: u8,
    priority_level: u8,
    pre_emption_capability: bool,
    pre_emption_vulnerability: bool,
) -> Avp {
    // Pre-emption enums per TS 29.212: ENABLED = 0, DISABLED = 1
    let pec = if pre_emption_capability { 0 } else { 1 };
    let pev = if pre_emption_vulnerability { 0 } else { 1 };
    Avp::vendor_mandatory(
        avp::EPS_SUBSCRIBED_QOS_PROFILE,
        NEXTGCORE_3GPP_VENDOR_ID,
        AvpData::Grouped(vec![
            Avp::vendor_mandatory(
                avp::QOS_CLASS_IDENTIFIER,
                NEXTGCORE_3GPP_VENDOR_ID,
                AvpData::Enumerated(qci as i32),
            ),
            Avp::vendor_mandatory(
                avp::ALLOCATION_RETENTION_PRIORITY,
                NEXTGCORE_3GPP_VENDOR_ID,
                AvpData::Grouped(vec![
                    Avp::vendor_mandatory(
                        avp::PRIORITY_LEVEL,
                        NEXTGCORE_3GPP_VENDOR_ID,
                        AvpData::Unsigned32(priority_level as u32),
                    ),
                    Avp::vendor_mandatory(
                        avp::PRE_EMPTION_CAPABILITY,
                        NEXTGCORE_3GPP_VENDOR_ID,
                        AvpData::Enumerated(pec),
                    ),
                    Avp::vendor_mandatory(
                        avp::PRE_EMPTION_VULNERABILITY,
                        NEXTGCORE_3GPP_VENDOR_ID,
                        AvpData::Enumerated(pev),
                    ),
                ]),
            ),
        ]),
    )
}

/// Build a single APN-Configuration grouped AVP (TS 29.272 7.3.35).
pub fn build_apn_configuration_avp(apn: &ApnConfiguration) -> Avp {
    let mut group = vec![
        Avp::vendor_mandatory(
            avp::CONTEXT_IDENTIFIER,
            NEXTGCORE_3GPP_VENDOR_ID,
            AvpData::Unsigned32(apn.context_identifier),
        ),
        Avp::vendor_mandatory(
            avp::PDN_TYPE,
            NEXTGCORE_3GPP_VENDOR_ID,
            AvpData::Enumerated(apn.pdn_type as i32),
        ),
        // Service-Selection is an IETF AVP (RFC 5778): no Vendor-Id
        Avp::mandatory(
            avp::SERVICE_SELECTION,
            AvpData::Utf8String(apn.service_selection.clone()),
        ),
        build_eps_subscribed_qos_profile_avp(
            apn.qci,
            apn.arp_priority_level,
            apn.arp_pre_emption_capability,
            apn.arp_pre_emption_vulnerability,
        ),
        build_ambr_avp(apn.ambr_uplink, apn.ambr_downlink),
    ];
    if let Some(cc) = apn.charging_characteristics {
        group.push(Avp::vendor_mandatory(
            avp::CHARGING_CHARACTERISTICS,
            NEXTGCORE_3GPP_VENDOR_ID,
            AvpData::OctetString(Bytes::copy_from_slice(&cc)),
        ));
    }
    Avp::vendor_mandatory(
        avp::APN_CONFIGURATION,
        NEXTGCORE_3GPP_VENDOR_ID,
        AvpData::Grouped(group),
    )
}

/// Build the Subscription-Data grouped AVP (TS 29.272 7.3.2) for ULA/IDR.
pub fn build_subscription_data_avp(sub: &SubscriptionData) -> Avp {
    let mut group: Vec<Avp> = Vec::new();

    if !sub.msisdn.is_empty() {
        group.push(Avp::vendor_mandatory(
            avp::MSISDN,
            NEXTGCORE_3GPP_VENDOR_ID,
            AvpData::OctetString(Bytes::copy_from_slice(&sub.msisdn)),
        ));
    }
    if !sub.a_msisdn.is_empty() {
        group.push(Avp::vendor_mandatory(
            avp::A_MSISDN,
            NEXTGCORE_3GPP_VENDOR_ID,
            AvpData::OctetString(Bytes::copy_from_slice(&sub.a_msisdn)),
        ));
    }
    group.push(Avp::vendor_mandatory(
        avp::SUBSCRIBER_STATUS,
        NEXTGCORE_3GPP_VENDOR_ID,
        AvpData::Enumerated(sub.subscriber_status as i32),
    ));
    if let Some(odb) = sub.operator_determined_barring {
        group.push(Avp::vendor_mandatory(
            avp::OPERATOR_DETERMINED_BARRING,
            NEXTGCORE_3GPP_VENDOR_ID,
            AvpData::Unsigned32(odb),
        ));
    }
    if let Some(ard) = sub.access_restriction_data {
        group.push(Avp::vendor_mandatory(
            avp::ACCESS_RESTRICTION_DATA,
            NEXTGCORE_3GPP_VENDOR_ID,
            AvpData::Unsigned32(ard),
        ));
    }
    group.push(Avp::vendor_mandatory(
        avp::NETWORK_ACCESS_MODE,
        NEXTGCORE_3GPP_VENDOR_ID,
        AvpData::Enumerated(sub.network_access_mode as i32),
    ));
    if sub.subscribed_rau_tau_timer > 0 {
        group.push(Avp::vendor_mandatory(
            avp::SUBSCRIBED_RAU_TAU_TIMER,
            NEXTGCORE_3GPP_VENDOR_ID,
            AvpData::Unsigned32(sub.subscribed_rau_tau_timer),
        ));
    }
    group.push(build_ambr_avp(sub.ambr_uplink, sub.ambr_downlink));
    if let Some(cc) = sub.charging_characteristics {
        group.push(Avp::vendor_mandatory(
            avp::CHARGING_CHARACTERISTICS,
            NEXTGCORE_3GPP_VENDOR_ID,
            AvpData::OctetString(Bytes::copy_from_slice(&cc)),
        ));
    }

    // APN-Configuration-Profile (TS 29.272 7.3.34)
    if !sub.apn_configs.is_empty() {
        let mut profile: Vec<Avp> = vec![
            Avp::vendor_mandatory(
                avp::CONTEXT_IDENTIFIER,
                NEXTGCORE_3GPP_VENDOR_ID,
                AvpData::Unsigned32(sub.context_identifier),
            ),
            Avp::vendor_mandatory(
                avp::ALL_APN_CONFIG_INC_IND,
                NEXTGCORE_3GPP_VENDOR_ID,
                // 0 = All_APN_CONFIGURATIONS_INCLUDED, 1 = MODIFIED/ADDED ONLY
                AvpData::Enumerated(if sub.all_apn_configs_included { 0 } else { 1 }),
            ),
        ];
        for apn in &sub.apn_configs {
            profile.push(build_apn_configuration_avp(apn));
        }
        group.push(Avp::vendor_mandatory(
            avp::APN_CONFIGURATION_PROFILE,
            NEXTGCORE_3GPP_VENDOR_ID,
            AvpData::Grouped(profile),
        ));
    }

    Avp::vendor_mandatory(
        avp::SUBSCRIPTION_DATA,
        NEXTGCORE_3GPP_VENDOR_ID,
        AvpData::Grouped(group),
    )
}

/// Parse an AMBR grouped AVP into (uplink, downlink) bps.
fn parse_ambr(avp_in: &Avp) -> (u64, u64) {
    let mut ul = 0u64;
    let mut dl = 0u64;
    if let Ok(group) = avp_in.parse_grouped() {
        if let Some(a) = crate::avp::find_avp(&group, avp::MAX_BANDWIDTH_UL) {
            ul = a.as_u32().unwrap_or(0) as u64;
        }
        if let Some(a) = crate::avp::find_avp(&group, avp::MAX_BANDWIDTH_DL) {
            dl = a.as_u32().unwrap_or(0) as u64;
        }
    }
    (ul, dl)
}

/// Parse a single APN-Configuration grouped AVP.
pub fn parse_apn_configuration_avp(avp_in: &Avp) -> ApnConfiguration {
    let mut apn = ApnConfiguration::default();
    let Ok(group) = avp_in.parse_grouped() else {
        return apn;
    };
    for inner in &group {
        match inner.code {
            avp::CONTEXT_IDENTIFIER => {
                apn.context_identifier = inner.as_u32().unwrap_or(0);
            }
            avp::PDN_TYPE => {
                apn.pdn_type = inner.as_u32().unwrap_or(pdn_type::IPV4) as u8;
            }
            avp::SERVICE_SELECTION => {
                if let Some(s) = inner.as_utf8_string() {
                    apn.service_selection = s.to_string();
                }
            }
            avp::CHARGING_CHARACTERISTICS => {
                if let Some(b) = inner.as_octet_string() {
                    if b.len() >= 2 {
                        apn.charging_characteristics = Some([b[0], b[1]]);
                    }
                }
            }
            avp::AMBR => {
                let (ul, dl) = parse_ambr(inner);
                apn.ambr_uplink = ul;
                apn.ambr_downlink = dl;
            }
            avp::EPS_SUBSCRIBED_QOS_PROFILE => {
                if let Ok(qg) = inner.parse_grouped() {
                    if let Some(a) = crate::avp::find_avp(&qg, avp::QOS_CLASS_IDENTIFIER) {
                        apn.qci = a.as_u32().unwrap_or(9) as u8;
                    }
                    if let Some(arp) = crate::avp::find_avp(&qg, avp::ALLOCATION_RETENTION_PRIORITY)
                    {
                        if let Ok(ag) = arp.parse_grouped() {
                            if let Some(a) = crate::avp::find_avp(&ag, avp::PRIORITY_LEVEL) {
                                apn.arp_priority_level = a.as_u32().unwrap_or(8) as u8;
                            }
                            if let Some(a) = crate::avp::find_avp(&ag, avp::PRE_EMPTION_CAPABILITY)
                            {
                                apn.arp_pre_emption_capability = a.as_u32().unwrap_or(1) == 0;
                            }
                            if let Some(a) =
                                crate::avp::find_avp(&ag, avp::PRE_EMPTION_VULNERABILITY)
                            {
                                apn.arp_pre_emption_vulnerability = a.as_u32().unwrap_or(1) == 0;
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }
    apn
}

/// Parse a Subscription-Data grouped AVP (in-memory or wire-decoded).
pub fn parse_subscription_data_avp(avp_in: &Avp) -> SubscriptionData {
    let mut sub = SubscriptionData::default();
    let Ok(group) = avp_in.parse_grouped() else {
        return sub;
    };
    for inner in &group {
        match inner.code {
            avp::MSISDN => {
                if let Some(b) = inner.as_octet_string() {
                    sub.msisdn = b.to_vec();
                }
            }
            avp::A_MSISDN => {
                if let Some(b) = inner.as_octet_string() {
                    sub.a_msisdn = b.to_vec();
                }
            }
            avp::SUBSCRIBER_STATUS => {
                sub.subscriber_status = inner.as_u32().unwrap_or(0);
            }
            avp::OPERATOR_DETERMINED_BARRING => {
                sub.operator_determined_barring = inner.as_u32();
            }
            avp::ACCESS_RESTRICTION_DATA => {
                sub.access_restriction_data = inner.as_u32();
            }
            avp::NETWORK_ACCESS_MODE => {
                sub.network_access_mode = inner.as_u32().unwrap_or(0);
            }
            avp::SUBSCRIBED_RAU_TAU_TIMER => {
                sub.subscribed_rau_tau_timer = inner.as_u32().unwrap_or(0);
            }
            avp::CHARGING_CHARACTERISTICS => {
                if let Some(b) = inner.as_octet_string() {
                    if b.len() >= 2 {
                        sub.charging_characteristics = Some([b[0], b[1]]);
                    }
                }
            }
            avp::AMBR => {
                let (ul, dl) = parse_ambr(inner);
                sub.ambr_uplink = ul;
                sub.ambr_downlink = dl;
            }
            avp::APN_CONFIGURATION_PROFILE => {
                if let Ok(pg) = inner.parse_grouped() {
                    for p in &pg {
                        match p.code {
                            avp::CONTEXT_IDENTIFIER => {
                                sub.context_identifier = p.as_u32().unwrap_or(0);
                            }
                            avp::ALL_APN_CONFIG_INC_IND => {
                                sub.all_apn_configs_included = p.as_u32().unwrap_or(0) == 0;
                            }
                            avp::APN_CONFIGURATION => {
                                sub.apn_configs.push(parse_apn_configuration_avp(p));
                            }
                            _ => {}
                        }
                    }
                }
            }
            _ => {}
        }
    }
    sub
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

    fn sample_subscription_data() -> SubscriptionData {
        SubscriptionData {
            msisdn: vec![0x21, 0x43, 0x65],
            a_msisdn: vec![],
            subscriber_status: 0,
            operator_determined_barring: None,
            access_restriction_data: Some(0x20),
            network_access_mode: 2, // ONLY_PACKET
            subscribed_rau_tau_timer: 12 * 60,
            ambr_uplink: 50_000_000,
            ambr_downlink: 100_000_000,
            context_identifier: 1,
            all_apn_configs_included: true,
            apn_configs: vec![
                ApnConfiguration {
                    context_identifier: 1,
                    service_selection: "internet".to_string(),
                    pdn_type: pdn_type::IPV4V6 as u8,
                    qci: 9,
                    arp_priority_level: 8,
                    arp_pre_emption_capability: false,
                    arp_pre_emption_vulnerability: true,
                    ambr_uplink: 50_000_000,
                    ambr_downlink: 100_000_000,
                    charging_characteristics: Some([0x0A, 0x00]),
                },
                ApnConfiguration {
                    context_identifier: 2,
                    service_selection: "ims".to_string(),
                    pdn_type: pdn_type::IPV4 as u8,
                    qci: 5,
                    arp_priority_level: 1,
                    arp_pre_emption_capability: true,
                    arp_pre_emption_vulnerability: false,
                    ambr_uplink: 1_000_000,
                    ambr_downlink: 2_000_000,
                    charging_characteristics: None,
                },
            ],
            charging_characteristics: Some([0x0A, 0x00]),
        }
    }

    /// Subscription-Data must survive a full wire round-trip:
    /// build -> encode message -> decode message (raw AVPs) -> parse.
    #[test]
    fn test_subscription_data_wire_roundtrip() {
        let sub = sample_subscription_data();

        let mut ula = DiameterMessage::new_request(cmd::UPDATE_LOCATION, S6A_APPLICATION_ID);
        ula.header.flags &= !crate::message::cmd_flags::REQUEST;
        ula.add_avp(build_subscription_data_avp(&sub));

        let encoded = ula.encode();
        let mut bytes = encoded.freeze();
        let decoded = DiameterMessage::decode(&mut bytes).unwrap();

        let sub_avp = decoded.find_avp(avp::SUBSCRIPTION_DATA).unwrap();
        // Wire conformance: V+M flags and 3GPP vendor id
        assert!(sub_avp.is_vendor_specific());
        assert!(sub_avp.is_mandatory());
        assert_eq!(sub_avp.vendor_id, Some(NEXTGCORE_3GPP_VENDOR_ID));

        let parsed = parse_subscription_data_avp(sub_avp);
        assert_eq!(parsed, sub);
    }

    /// A strict peer must see Re-Synchronization-Info INSIDE
    /// Requested-EUTRAN-Authentication-Info, not at top level.
    #[test]
    fn test_resync_info_inside_requested_eutran_auth_info() {
        let mut air = create_air(
            "session-resync",
            "mme.example.org",
            "example.org",
            "example.org",
            "001010123456789",
            &[0x00, 0xF1, 0x10],
            1,
        );
        let rand = [0xAA; 16];
        let auts = [0xBB; 14];
        assert!(add_resync_info(&mut air, &rand, &auts));

        // Encode/decode to simulate the wire
        let encoded = air.encode();
        let mut bytes = encoded.freeze();
        let decoded = DiameterMessage::decode(&mut bytes).unwrap();

        // Not top-level
        assert!(decoded.find_avp(avp::RE_SYNC_INFO).is_none());
        // Inside the grouped AVP
        let (r, a) = find_resync_info(&decoded).unwrap();
        assert_eq!(r, rand);
        assert_eq!(a, auts);
        // Number-Of-Requested-Vectors still present alongside
        assert_eq!(find_num_requested_vectors(&decoded), Some(1));
    }

    #[test]
    fn test_resync_info_requires_grouped_avp() {
        let mut msg =
            DiameterMessage::new_request(cmd::AUTHENTICATION_INFORMATION, S6A_APPLICATION_ID);
        assert!(!add_resync_info(&mut msg, &[0u8; 16], &[0u8; 14]));
        assert!(find_resync_info(&msg).is_none());
    }

    #[test]
    fn test_experimental_result_roundtrip() {
        let mut msg = DiameterMessage::new_request(cmd::UPDATE_LOCATION, S6A_APPLICATION_ID);
        msg.add_avp(experimental_result_avp(exp_result::ERROR_USER_UNKNOWN));

        let encoded = msg.encode();
        let mut bytes = encoded.freeze();
        let decoded = DiameterMessage::decode(&mut bytes).unwrap();

        assert_eq!(
            experimental_result_code(&decoded),
            Some(exp_result::ERROR_USER_UNKNOWN)
        );
    }

    #[test]
    fn test_authentication_info_multi_vector_wire_roundtrip() {
        let v1 = EUtranVector {
            rand: [1; 16],
            xres: vec![2; 8],
            autn: [3; 16],
            kasme: [4; 32],
        };
        let v2 = EUtranVector {
            rand: [5; 16],
            xres: vec![6; 8],
            autn: [7; 16],
            kasme: [8; 32],
        };

        let mut aia =
            DiameterMessage::new_request(cmd::AUTHENTICATION_INFORMATION, S6A_APPLICATION_ID);
        aia.header.flags &= !crate::message::cmd_flags::REQUEST;
        aia.add_avp(Avp::vendor_mandatory(
            avp::AUTHENTICATION_INFO,
            NEXTGCORE_3GPP_VENDOR_ID,
            AvpData::Grouped(vec![
                build_e_utran_vector_avp(Some(1), &v1),
                build_e_utran_vector_avp(Some(2), &v2),
            ]),
        ));

        let encoded = aia.encode();
        let mut bytes = encoded.freeze();
        let decoded = DiameterMessage::decode(&mut bytes).unwrap();

        let vectors = parse_authentication_info(&decoded);
        assert_eq!(vectors.len(), 2);
        assert_eq!(vectors[0].rand, v1.rand);
        assert_eq!(vectors[0].xres, v1.xres);
        assert_eq!(vectors[0].autn, v1.autn);
        assert_eq!(vectors[0].kasme, v1.kasme);
        assert_eq!(vectors[1].rand, v2.rand);
    }

    /// Service-Selection must be encoded without a Vendor-Id (RFC 5778).
    #[test]
    fn test_service_selection_is_not_vendor_specific() {
        let apn = sample_subscription_data().apn_configs[0].clone();
        let apn_avp = build_apn_configuration_avp(&apn);
        let group = apn_avp.parse_grouped().unwrap();
        let ss = crate::avp::find_avp(&group, avp::SERVICE_SELECTION).unwrap();
        assert!(!ss.is_vendor_specific());
        assert!(ss.is_mandatory());
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
