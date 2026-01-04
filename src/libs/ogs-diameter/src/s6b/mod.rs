//! S6b Interface - PGW/SMF <-> 3GPP AAA Server (3GPP TS 29.273)
//!
//! The S6b interface is used for non-3GPP access (WiFi/ePDG) authorization:
//! - AA-Request/Answer (AAR/AAA) - Authentication and Authorization
//! - Session-Termination-Request/Answer (STR/STA) - Session termination
//! - Abort-Session-Request/Answer (ASR/ASA) - Server-initiated abort
//! - Re-Auth-Request/Answer (RAR/RAA) - Re-authorization

use bytes::Bytes;

use crate::avp::{Avp, AvpData};
use crate::common::avp_code;
use crate::message::DiameterMessage;
use crate::OGS_3GPP_VENDOR_ID;

/// S6b Application ID (3GPP TS 29.273)
pub const S6B_APPLICATION_ID: u32 = 16777272;

/// S6b Command Codes
pub mod cmd {
    /// AA-Request/Answer (Authorization-Authentication)
    pub const AA: u32 = 265;
    /// Session-Termination-Request/Answer
    pub const SESSION_TERMINATION: u32 = 275;
    /// Abort-Session-Request/Answer
    pub const ABORT_SESSION: u32 = 274;
    /// Re-Auth-Request/Answer
    pub const RE_AUTH: u32 = 258;
}

/// S6b AVP Codes (3GPP specific)
pub mod avp {
    /// MIP6-Feature-Vector (RFC 5447)
    pub const MIP6_FEATURE_VECTOR: u32 = 124;
    /// MIP6-Agent-Info (RFC 5447)
    pub const MIP6_AGENT_INFO: u32 = 486;
    /// MIP-Home-Agent-Address (RFC 4004)
    pub const MIP_HOME_AGENT_ADDRESS: u32 = 334;
    /// MIP-Home-Agent-Host (RFC 4004)
    pub const MIP_HOME_AGENT_HOST: u32 = 348;
    /// Visited-Network-Identifier (3GPP)
    pub const VISITED_NETWORK_IDENTIFIER: u32 = 600;
    /// Service-Selection (RFC 5778)
    pub const SERVICE_SELECTION: u32 = 493;
    /// APN-Configuration (3GPP)
    pub const APN_CONFIGURATION: u32 = 1430;
    /// Context-Identifier (3GPP)
    pub const CONTEXT_IDENTIFIER: u32 = 1423;
    /// PDN-Type (3GPP)
    pub const PDN_TYPE: u32 = 1456;
    /// Served-Party-IP-Address (3GPP)
    pub const SERVED_PARTY_IP_ADDRESS: u32 = 848;
    /// AN-Trusted (3GPP)
    pub const AN_TRUSTED: u32 = 1503;
    /// Mobile-Node-Identifier (RFC 5779)
    pub const MOBILE_NODE_IDENTIFIER: u32 = 506;
    /// TWAN-Identifier (3GPP)
    pub const TWAN_IDENTIFIER: u32 = 29;
    /// SSID (3GPP)
    pub const SSID: u32 = 1524;
    /// BSSID (3GPP)
    pub const BSSID: u32 = 1525;
    /// WLAN-Identifier (3GPP)
    pub const WLAN_IDENTIFIER: u32 = 1509;
    /// 3GPP-Charging-Characteristics
    pub const CHARGING_CHARACTERISTICS: u32 = 13;
    /// RAT-Type
    pub const RAT_TYPE: u32 = 1032;
    /// Terminal-Information
    pub const TERMINAL_INFORMATION: u32 = 1401;
    /// IMEI
    pub const IMEI: u32 = 1402;
    /// Software-Version
    pub const SOFTWARE_VERSION: u32 = 1403;
}

/// MIP6-Feature-Vector flags (RFC 5447, 3GPP TS 29.273)
pub mod mip6_feature_vector {
    /// Mobile IPv4 supported
    pub const MIP4_SUPPORTED: u64 = 0x0000000000000001;
    /// Local Home Agent Assignment supported
    pub const LOCAL_HA_SUPPORTED: u64 = 0x0000000000000002;
    /// GTPv2 Supported
    pub const GTPV2_SUPPORTED: u64 = 0x0000400000000000;
    /// PMIPv6 Supported
    pub const PMIP6_SUPPORTED: u64 = 0x0010000000000000;
    /// IP4_HOA_SUPPORTED
    pub const IP4_HOA_SUPPORTED: u64 = 0x0000000000000004;
    /// IP6_HOA_SUPPORTED
    pub const IP6_HOA_SUPPORTED: u64 = 0x0000000000000010;
}

/// RAT Type values (3GPP TS 29.212)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum RatType {
    Wlan = 0,
    VirtualLine = 1,
    Eutran = 1004,
    Utran = 1005,
    Geran = 1006,
    Gan = 1007,
    HspaEvolution = 1008,
    Eutran5Gc = 1009,
    NrU = 1010,
    Nr = 1011,
    EutranNb = 1012,
}

impl From<u32> for RatType {
    fn from(value: u32) -> Self {
        match value {
            0 => RatType::Wlan,
            1 => RatType::VirtualLine,
            1004 => RatType::Eutran,
            1005 => RatType::Utran,
            1006 => RatType::Geran,
            1007 => RatType::Gan,
            1008 => RatType::HspaEvolution,
            1009 => RatType::Eutran5Gc,
            1010 => RatType::NrU,
            1011 => RatType::Nr,
            1012 => RatType::EutranNb,
            _ => RatType::Wlan,
        }
    }
}

/// AN-Trusted values
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum AnTrusted {
    Trusted = 0,
    Untrusted = 1,
}

/// PDN Type values
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum PdnType {
    Ipv4 = 0,
    Ipv6 = 1,
    Ipv4v6 = 2,
    Ipv4OrIpv6 = 3,
}

/// Auth-Request-Type values (RFC 6733)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum AuthRequestType {
    AuthenticateOnly = 1,
    AuthorizeOnly = 2,
    AuthorizeAuthenticate = 3,
}

/// Termination-Cause values (RFC 6733)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum TerminationCause {
    DiameterLogout = 1,
    DiameterServiceNotProvided = 2,
    DiameterBadAnswer = 3,
    DiameterAdministrative = 4,
    DiameterLinkBroken = 5,
    DiameterAuthExpired = 6,
    DiameterUserMoved = 7,
    DiameterSessionTimeout = 8,
}

/// S6b message structure
#[derive(Debug, Clone)]
pub struct S6bMessage {
    /// Command code
    pub cmd_code: u32,
    /// Result code
    pub result_code: u32,
    /// Error pointer
    pub err: Option<u32>,
    /// Experimental error pointer
    pub exp_err: Option<u32>,
}

impl S6bMessage {
    /// Create a new S6b message
    pub fn new(cmd_code: u32) -> Self {
        Self {
            cmd_code,
            result_code: 0,
            err: None,
            exp_err: None,
        }
    }

    /// Check if result indicates success
    pub fn is_success(&self) -> bool {
        self.result_code == 2001 // DIAMETER_SUCCESS
    }
}

/// Create an AA-Request (AAR) for S6b
pub fn create_aar(
    session_id: &str,
    origin_host: &str,
    origin_realm: &str,
    destination_realm: &str,
    destination_host: Option<&str>,
    user_name: &str,
    rat_type: RatType,
    mip6_feature_vector: u64,
    visited_network_identifier: &str,
    service_selection: &str,
) -> DiameterMessage {
    let mut msg = DiameterMessage::new_request(cmd::AA, S6B_APPLICATION_ID);

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

    // Destination-Host (optional)
    if let Some(host) = destination_host {
        msg.add_avp(Avp::mandatory(
            avp_code::DESTINATION_HOST,
            AvpData::DiameterIdentity(host.to_string()),
        ));
    }

    // Auth-Application-Id
    msg.add_avp(Avp::mandatory(
        avp_code::AUTH_APPLICATION_ID,
        AvpData::Unsigned32(S6B_APPLICATION_ID),
    ));

    // Auth-Request-Type (AUTHORIZE_ONLY for S6b)
    msg.add_avp(Avp::mandatory(
        avp_code::AUTH_REQUEST_TYPE,
        AvpData::Enumerated(AuthRequestType::AuthorizeOnly as i32),
    ));

    // User-Name (IMSI@nai.epc.mncXXX.mccXXX.3gppnetwork.org)
    msg.add_avp(Avp::mandatory(
        avp_code::USER_NAME,
        AvpData::Utf8String(user_name.to_string()),
    ));

    // RAT-Type
    msg.add_avp(Avp::vendor_mandatory(
        avp::RAT_TYPE,
        OGS_3GPP_VENDOR_ID,
        AvpData::Enumerated(rat_type as i32),
    ));

    // MIP6-Feature-Vector
    msg.add_avp(Avp::mandatory(
        avp::MIP6_FEATURE_VECTOR,
        AvpData::Unsigned64(mip6_feature_vector),
    ));

    // Visited-Network-Identifier
    msg.add_avp(Avp::vendor_mandatory(
        avp::VISITED_NETWORK_IDENTIFIER,
        OGS_3GPP_VENDOR_ID,
        AvpData::OctetString(Bytes::copy_from_slice(visited_network_identifier.as_bytes())),
    ));

    // Service-Selection (APN)
    msg.add_avp(Avp::mandatory(
        avp::SERVICE_SELECTION,
        AvpData::Utf8String(service_selection.to_string()),
    ));

    msg
}

/// Add MIP6-Agent-Info AVP with home agent addresses
pub fn add_mip6_agent_info(
    msg: &mut DiameterMessage,
    ipv4_addr: Option<std::net::Ipv4Addr>,
    ipv6_addr: Option<std::net::Ipv6Addr>,
) {
    use std::net::IpAddr;

    let mut grouped_data = Vec::new();

    if let Some(addr) = ipv4_addr {
        grouped_data.push(Avp::mandatory(
            avp::MIP_HOME_AGENT_ADDRESS,
            AvpData::Address(IpAddr::V4(addr)),
        ));
    }

    if let Some(addr) = ipv6_addr {
        grouped_data.push(Avp::mandatory(
            avp::MIP_HOME_AGENT_ADDRESS,
            AvpData::Address(IpAddr::V6(addr)),
        ));
    }

    if !grouped_data.is_empty() {
        msg.add_avp(Avp::mandatory(
            avp::MIP6_AGENT_INFO,
            AvpData::Grouped(grouped_data),
        ));
    }
}

/// Create a Session-Termination-Request (STR) for S6b
pub fn create_str(
    session_id: &str,
    origin_host: &str,
    origin_realm: &str,
    destination_realm: &str,
    user_name: &str,
    termination_cause: TerminationCause,
) -> DiameterMessage {
    let mut msg = DiameterMessage::new_request(cmd::SESSION_TERMINATION, S6B_APPLICATION_ID);

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

    // Auth-Application-Id
    msg.add_avp(Avp::mandatory(
        avp_code::AUTH_APPLICATION_ID,
        AvpData::Unsigned32(S6B_APPLICATION_ID),
    ));

    // Termination-Cause
    msg.add_avp(Avp::mandatory(
        avp_code::TERMINATION_CAUSE,
        AvpData::Enumerated(termination_cause as i32),
    ));

    // User-Name
    msg.add_avp(Avp::mandatory(
        avp_code::USER_NAME,
        AvpData::Utf8String(user_name.to_string()),
    ));

    msg
}

/// Create an AA-Answer (AAA) response
pub fn create_aaa(
    request: &DiameterMessage,
    origin_host: &str,
    origin_realm: &str,
    result_code: u32,
) -> DiameterMessage {
    let mut msg = DiameterMessage::new_answer(request);

    // Copy Session-Id from request if present
    if let Some(session_avp) = request.find_avp(avp_code::SESSION_ID) {
        msg.add_avp(session_avp.clone());
    }

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

    // Result-Code
    msg.add_avp(Avp::mandatory(
        avp_code::RESULT_CODE,
        AvpData::Unsigned32(result_code),
    ));

    // Auth-Application-Id
    msg.add_avp(Avp::mandatory(
        avp_code::AUTH_APPLICATION_ID,
        AvpData::Unsigned32(S6B_APPLICATION_ID),
    ));

    msg
}

/// Create a Session-Termination-Answer (STA) response
pub fn create_sta(
    request: &DiameterMessage,
    origin_host: &str,
    origin_realm: &str,
    result_code: u32,
) -> DiameterMessage {
    let mut msg = DiameterMessage::new_answer(request);

    // Copy Session-Id from request if present
    if let Some(session_avp) = request.find_avp(avp_code::SESSION_ID) {
        msg.add_avp(session_avp.clone());
    }

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

    // Result-Code
    msg.add_avp(Avp::mandatory(
        avp_code::RESULT_CODE,
        AvpData::Unsigned32(result_code),
    ));

    msg
}

/// Parse WLAN identifier from TWAN-Identifier AVP
#[derive(Debug, Clone)]
pub struct WlanIdentifier {
    pub ssid: Option<String>,
    pub bssid: Option<[u8; 6]>,
}

impl WlanIdentifier {
    pub fn new() -> Self {
        Self {
            ssid: None,
            bssid: None,
        }
    }
}

impl Default for WlanIdentifier {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_aar() {
        let msg = create_aar(
            "session123;app_s6b",
            "smf.epc.mnc001.mcc001.3gppnetwork.org",
            "epc.mnc001.mcc001.3gppnetwork.org",
            "epc.mnc001.mcc001.3gppnetwork.org",
            None,
            "123456789012345@nai.epc.mnc001.mcc001.3gppnetwork.org",
            RatType::Wlan,
            mip6_feature_vector::GTPV2_SUPPORTED,
            "mnc001.mcc001.3gppnetwork.org",
            "internet",
        );

        assert_eq!(msg.header.command_code, cmd::AA);
        assert_eq!(msg.header.application_id, S6B_APPLICATION_ID);
        assert!(msg.header.is_request());
    }

    #[test]
    fn test_create_str() {
        let msg = create_str(
            "session123;app_s6b",
            "smf.epc.mnc001.mcc001.3gppnetwork.org",
            "epc.mnc001.mcc001.3gppnetwork.org",
            "epc.mnc001.mcc001.3gppnetwork.org",
            "123456789012345@nai.epc.mnc001.mcc001.3gppnetwork.org",
            TerminationCause::DiameterLogout,
        );

        assert_eq!(msg.header.command_code, cmd::SESSION_TERMINATION);
        assert_eq!(msg.header.application_id, S6B_APPLICATION_ID);
        assert!(msg.header.is_request());
    }

    #[test]
    fn test_rat_type_conversion() {
        assert_eq!(RatType::from(0), RatType::Wlan);
        assert_eq!(RatType::from(1004), RatType::Eutran);
        assert_eq!(RatType::from(1011), RatType::Nr);
    }

    #[test]
    fn test_s6b_message() {
        let mut msg = S6bMessage::new(cmd::AA);
        msg.result_code = 2001;
        assert!(msg.is_success());

        msg.result_code = 5001;
        assert!(!msg.is_success());
    }
}
