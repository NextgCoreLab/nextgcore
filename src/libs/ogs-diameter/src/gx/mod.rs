//! Gx Interface - PCEF <-> PCRF (3GPP TS 29.212)
//!
//! The Gx interface is used for Policy and Charging Control:
//! - Credit-Control-Request/Answer (CCR/CCA)
//! - Re-Auth-Request/Answer (RAR/RAA)

use bytes::Bytes;

use crate::avp::{Avp, AvpData};
use crate::common::avp_code;
use crate::message::DiameterMessage;
use crate::OGS_3GPP_VENDOR_ID;

/// Gx Application ID (3GPP TS 29.212)
pub const GX_APPLICATION_ID: u32 = 16777238;

/// Gx Command Codes
pub mod cmd {
    /// Credit-Control-Request/Answer
    pub const CREDIT_CONTROL: u32 = 272;
    /// Re-Auth-Request/Answer
    pub const RE_AUTH: u32 = 258;
}

/// Gx AVP Codes
pub mod avp {
    /// Re-Auth-Request-Type
    pub const RE_AUTH_REQUEST_TYPE: u32 = 285;
    /// CC-Request-Number
    pub const CC_REQUEST_NUMBER: u32 = 415;
    /// CC-Request-Type
    pub const CC_REQUEST_TYPE: u32 = 416;
    /// Default-EPS-Bearer-QoS
    pub const DEFAULT_EPS_BEARER_QOS: u32 = 1049;
    /// Supported-Features
    pub const SUPPORTED_FEATURES: u32 = 628;
    /// Charging-Rule-Install
    pub const CHARGING_RULE_INSTALL: u32 = 1001;
    /// Charging-Rule-Remove
    pub const CHARGING_RULE_REMOVE: u32 = 1002;
    /// Charging-Rule-Definition
    pub const CHARGING_RULE_DEFINITION: u32 = 1003;
    /// Charging-Rule-Name
    pub const CHARGING_RULE_NAME: u32 = 1005;
    /// Flow-Information
    pub const FLOW_INFORMATION: u32 = 1058;
    /// Flow-Status
    pub const FLOW_STATUS: u32 = 511;
    /// QoS-Information
    pub const QOS_INFORMATION: u32 = 1016;
    /// Precedence
    pub const PRECEDENCE: u32 = 1010;
    /// Rating-Group
    pub const RATING_GROUP: u32 = 432;
    /// Feature-List-ID
    pub const FEATURE_LIST_ID: u32 = 629;
    /// Feature-List
    pub const FEATURE_LIST: u32 = 630;
    /// Framed-IP-Address
    pub const FRAMED_IP_ADDRESS: u32 = 8;
    /// Framed-IPv6-Prefix
    pub const FRAMED_IPV6_PREFIX: u32 = 97;
    /// IP-CAN-Type
    pub const IP_CAN_TYPE: u32 = 1027;
    /// QoS-Class-Identifier
    pub const QOS_CLASS_IDENTIFIER: u32 = 1028;
    /// Max-Requested-Bandwidth-UL
    pub const MAX_REQUESTED_BANDWIDTH_UL: u32 = 516;
    /// Max-Requested-Bandwidth-DL
    pub const MAX_REQUESTED_BANDWIDTH_DL: u32 = 515;
    /// Guaranteed-Bitrate-UL
    pub const GUARANTEED_BITRATE_UL: u32 = 1026;
    /// Guaranteed-Bitrate-DL
    pub const GUARANTEED_BITRATE_DL: u32 = 1025;
    /// Allocation-Retention-Priority
    pub const ALLOCATION_RETENTION_PRIORITY: u32 = 1034;
    /// Priority-Level
    pub const PRIORITY_LEVEL: u32 = 1046;
    /// Pre-emption-Capability
    pub const PRE_EMPTION_CAPABILITY: u32 = 1047;
    /// Pre-emption-Vulnerability
    pub const PRE_EMPTION_VULNERABILITY: u32 = 1048;
    /// APN-Aggregate-Max-Bitrate-UL
    pub const APN_AGGREGATE_MAX_BITRATE_UL: u32 = 1041;
    /// APN-Aggregate-Max-Bitrate-DL
    pub const APN_AGGREGATE_MAX_BITRATE_DL: u32 = 1040;
    /// 3GPP-User-Location-Info
    pub const USER_LOCATION_INFO: u32 = 22;
    /// Called-Station-Id
    pub const CALLED_STATION_ID: u32 = 30;
    /// 3GPP-MS-TimeZone
    pub const MS_TIMEZONE: u32 = 23;
    /// 3GPP-Charging-Characteristics
    pub const CHARGING_CHARACTERISTICS: u32 = 13;
    /// Event-Trigger
    pub const EVENT_TRIGGER: u32 = 1006;
    /// Bearer-Control-Mode
    pub const BEARER_CONTROL_MODE: u32 = 1023;
    /// Charging-Rule-Base-Name
    pub const CHARGING_RULE_BASE_NAME: u32 = 1004;
    /// Flow-Direction
    pub const FLOW_DIRECTION: u32 = 1080;
    /// Flow-Description
    pub const FLOW_DESCRIPTION: u32 = 507;
    /// Media-Component-Description
    pub const MEDIA_COMPONENT_DESCRIPTION: u32 = 517;
    /// Media-Component-Number
    pub const MEDIA_COMPONENT_NUMBER: u32 = 518;
    /// Media-Type
    pub const MEDIA_TYPE: u32 = 520;
    /// RR-Bandwidth
    pub const RR_BANDWIDTH: u32 = 521;
    /// RS-Bandwidth
    pub const RS_BANDWIDTH: u32 = 522;
    /// Codec-Data
    pub const CODEC_DATA: u32 = 524;
    /// Media-Sub-Component
    pub const MEDIA_SUB_COMPONENT: u32 = 519;
    /// Flow-Number
    pub const FLOW_NUMBER: u32 = 509;
    /// Flow-Usage
    pub const FLOW_USAGE: u32 = 512;
    /// 3GPP-SGSN-MCC-MNC
    pub const SGSN_MCC_MNC: u32 = 18;
    /// AN-GW-Address
    pub const AN_GW_ADDRESS: u32 = 1050;
    /// Online
    pub const ONLINE: u32 = 1009;
    /// Offline
    pub const OFFLINE: u32 = 1008;
    /// Access-Network-Charging-Address
    pub const ACCESS_NETWORK_CHARGING_ADDRESS: u32 = 501;
    /// Access-Network-Charging-Identifier-Gx
    pub const ACCESS_NETWORK_CHARGING_IDENTIFIER_GX: u32 = 1022;
    /// Access-Network-Charging-Identifier-Value
    pub const ACCESS_NETWORK_CHARGING_IDENTIFIER_VALUE: u32 = 503;
    /// AN-Trusted
    pub const AN_TRUSTED: u32 = 1503;
}


/// IP-CAN Type values
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum IpCanType {
    Gprs3Gpp = 0,
    Docsis = 1,
    XDsl = 2,
    WiMax = 3,
    Gpp2_3 = 4,
    Eps3Gpp = 5,
    Non3GppEps = 6,
}

/// 3GPP User Location Info Type
pub mod user_location_info_type {
    pub const TAI: u8 = 128;
    pub const ECGI: u8 = 129;
    pub const TAI_AND_ECGI: u8 = 130;
}

/// CC-Request-Type values
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum CcRequestType {
    InitialRequest = 1,
    UpdateRequest = 2,
    TerminationRequest = 3,
    EventRequest = 4,
}

impl From<u32> for CcRequestType {
    fn from(value: u32) -> Self {
        match value {
            1 => CcRequestType::InitialRequest,
            2 => CcRequestType::UpdateRequest,
            3 => CcRequestType::TerminationRequest,
            4 => CcRequestType::EventRequest,
            _ => CcRequestType::InitialRequest,
        }
    }
}

/// Online/Offline charging
pub mod charging {
    pub const DISABLE_ONLINE: u32 = 0;
    pub const ENABLE_ONLINE: u32 = 1;
    pub const DISABLE_OFFLINE: u32 = 0;
    pub const ENABLE_OFFLINE: u32 = 1;
}

/// AN-Trusted values
pub mod an_trusted {
    pub const TRUSTED: u32 = 0;
    pub const UNTRUSTED: u32 = 1;
}

/// Gx Experimental Result Codes
pub mod exp_result {
    pub const ERROR_LATE_OVERLAPPING_REQUEST: u32 = 5453;
    pub const ERROR_TIMED_OUT_REQUEST: u32 = 5454;
    pub const ERROR_INITIAL_PARAMETERS: u32 = 5140;
    pub const ERROR_TRIGGER_EVENT: u32 = 5141;
    pub const PCC_RULE_EVENT: u32 = 5142;
    pub const ERROR_BEARER_NOT_AUTHORIZED: u32 = 5143;
    pub const ERROR_TRAFFIC_MAPPING_INFO_REJECTED: u32 = 5144;
    pub const ERROR_CONFLICTING_REQUEST: u32 = 5147;
    pub const ADC_RULE_EVENT: u32 = 5148;
    pub const ERROR_NBIFOM_NOT_AUTHORIZED: u32 = 5149;
}

/// Gx message
#[derive(Debug, Clone)]
pub struct GxMessage {
    /// Command code
    pub cmd_code: u16,
    /// Result code
    pub result_code: u32,
    /// Error pointer
    pub err: Option<u32>,
    /// Experimental error pointer
    pub exp_err: Option<u32>,
    /// CC-Request-Type
    pub cc_request_type: CcRequestType,
    // Note: session_data would be a complex type from ogs-core
}

impl GxMessage {
    /// Create a new Gx message
    pub fn new(cmd_code: u16) -> Self {
        Self {
            cmd_code,
            result_code: 0,
            err: None,
            exp_err: None,
            cc_request_type: CcRequestType::InitialRequest,
        }
    }
}

/// Create a Credit-Control-Request (CCR)
pub fn create_ccr(
    session_id: &str,
    origin_host: &str,
    origin_realm: &str,
    destination_realm: &str,
    cc_request_type: CcRequestType,
    cc_request_number: u32,
) -> DiameterMessage {
    let mut msg = DiameterMessage::new_request(cmd::CREDIT_CONTROL, GX_APPLICATION_ID);

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
        AvpData::Unsigned32(GX_APPLICATION_ID),
    ));

    // CC-Request-Type
    msg.add_avp(Avp::mandatory(
        avp::CC_REQUEST_TYPE,
        AvpData::Enumerated(cc_request_type as i32),
    ));

    // CC-Request-Number
    msg.add_avp(Avp::mandatory(
        avp::CC_REQUEST_NUMBER,
        AvpData::Unsigned32(cc_request_number),
    ));

    msg
}

/// Add IP-CAN-Type AVP to message
pub fn add_ip_can_type(msg: &mut DiameterMessage, ip_can_type: IpCanType) {
    msg.add_avp(Avp::vendor_mandatory(
        avp::IP_CAN_TYPE,
        OGS_3GPP_VENDOR_ID,
        AvpData::Enumerated(ip_can_type as i32),
    ));
}

/// Add Called-Station-Id (APN) AVP to message
pub fn add_called_station_id(msg: &mut DiameterMessage, apn: &str) {
    msg.add_avp(Avp::mandatory(
        avp::CALLED_STATION_ID,
        AvpData::Utf8String(apn.to_string()),
    ));
}

/// Add Framed-IP-Address AVP to message
pub fn add_framed_ip_address(msg: &mut DiameterMessage, addr: std::net::Ipv4Addr) {
    msg.add_avp(Avp::mandatory(
        avp::FRAMED_IP_ADDRESS,
        AvpData::OctetString(Bytes::copy_from_slice(&addr.octets())),
    ));
}

/// Add Framed-IPv6-Prefix AVP to message
pub fn add_framed_ipv6_prefix(msg: &mut DiameterMessage, prefix: &[u8]) {
    msg.add_avp(Avp::mandatory(
        avp::FRAMED_IPV6_PREFIX,
        AvpData::OctetString(Bytes::copy_from_slice(prefix)),
    ));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_ccr() {
        let msg = create_ccr(
            "session123",
            "pcef.epc.mnc001.mcc001.3gppnetwork.org",
            "epc.mnc001.mcc001.3gppnetwork.org",
            "epc.mnc001.mcc001.3gppnetwork.org",
            CcRequestType::InitialRequest,
            0,
        );

        assert_eq!(msg.header.command_code, cmd::CREDIT_CONTROL);
        assert_eq!(msg.header.application_id, GX_APPLICATION_ID);
        assert!(msg.header.is_request());
    }

    #[test]
    fn test_cc_request_type_conversion() {
        assert_eq!(CcRequestType::from(1), CcRequestType::InitialRequest);
        assert_eq!(CcRequestType::from(2), CcRequestType::UpdateRequest);
        assert_eq!(CcRequestType::from(3), CcRequestType::TerminationRequest);
        assert_eq!(CcRequestType::from(4), CcRequestType::EventRequest);
    }
}
