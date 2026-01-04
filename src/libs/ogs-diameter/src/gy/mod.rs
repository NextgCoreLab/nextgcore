//! Gy Interface - CTF <-> OCS (3GPP TS 32.299)
//!
//! The Gy interface is used for Online Charging:
//! - Credit-Control-Request/Answer (CCR/CCA)
//! - Re-Auth-Request/Answer (RAR/RAA)

use crate::avp::{Avp, AvpData};
use crate::common::avp_code;
use crate::message::DiameterMessage;


/// Gy Application ID (Diameter Credit-Control Application)
pub const GY_APPLICATION_ID: u32 = 4;

/// Gy Command Codes
pub mod cmd {
    /// Credit-Control-Request/Answer
    pub const CREDIT_CONTROL: u32 = 272;
    /// Re-Auth-Request/Answer
    pub const RE_AUTH: u32 = 258;
}

/// Gy AVP Codes
pub mod avp {
    /// Re-Auth-Request-Type
    pub const RE_AUTH_REQUEST_TYPE: u32 = 285;
    /// CC-Input-Octets
    pub const CC_INPUT_OCTETS: u32 = 412;
    /// CC-Output-Octets
    pub const CC_OUTPUT_OCTETS: u32 = 414;
    /// CC-Request-Number
    pub const CC_REQUEST_NUMBER: u32 = 415;
    /// CC-Request-Type
    pub const CC_REQUEST_TYPE: u32 = 416;
    /// CC-Time
    pub const CC_TIME: u32 = 420;
    /// CC-Total-Octets
    pub const CC_TOTAL_OCTETS: u32 = 421;
    /// Final-Unit-Indication
    pub const FINAL_UNIT_INDICATION: u32 = 430;
    /// Granted-Service-Unit
    pub const GRANTED_SERVICE_UNIT: u32 = 431;
    /// Validity-Time
    pub const VALIDITY_TIME: u32 = 448;
    /// Final-Unit-Action
    pub const FINAL_UNIT_ACTION: u32 = 449;
    /// Multiple-Services-Credit-Control
    pub const MULTIPLE_SERVICES_CREDIT_CONTROL: u32 = 456;
    /// Supported-Features
    pub const SUPPORTED_FEATURES: u32 = 628;
    /// Time-Quota-Threshold
    pub const TIME_QUOTA_THRESHOLD: u32 = 868;
    /// Volume-Quota-Threshold
    pub const VOLUME_QUOTA_THRESHOLD: u32 = 869;
    /// Charging-Rule-Base-Name
    pub const CHARGING_RULE_BASE_NAME: u32 = 1004;
    /// Flow-Information
    pub const FLOW_INFORMATION: u32 = 1058;
    /// QoS-Information
    pub const QOS_INFORMATION: u32 = 1016;
    /// Requested-Action
    pub const REQUESTED_ACTION: u32 = 436;
    /// AoC-Request-Type
    pub const AOC_REQUEST_TYPE: u32 = 2055;
    /// Multiple-Services-Indicator
    pub const MULTIPLE_SERVICES_INDICATOR: u32 = 455;
    /// Requested-Service-Unit
    pub const REQUESTED_SERVICE_UNIT: u32 = 437;
    /// Used-Service-Unit
    pub const USED_SERVICE_UNIT: u32 = 446;
    /// CC-Service-Specific-Units
    pub const CC_SERVICE_SPECIFIC_UNITS: u32 = 417;
    /// Reporting-Reason
    pub const REPORTING_REASON: u32 = 872;
    /// Service-Identifier
    pub const SERVICE_IDENTIFIER: u32 = 439;
    /// Service-Information
    pub const SERVICE_INFORMATION: u32 = 873;
    /// PS-Information
    pub const PS_INFORMATION: u32 = 874;
    /// 3GPP-Charging-Id
    pub const CHARGING_ID: u32 = 2;
    /// 3GPP-PDP-Type
    pub const PDP_TYPE: u32 = 3;
    /// PDP-Address
    pub const PDP_ADDRESS: u32 = 1227;
    /// SGSN-Address
    pub const SGSN_ADDRESS: u32 = 1228;
    /// GGSN-Address
    pub const GGSN_ADDRESS: u32 = 847;
    /// 3GPP-NSAPI
    pub const NSAPI: u32 = 10;
    /// 3GPP-Selection-Mode
    pub const SELECTION_MODE: u32 = 12;
    /// 3GPP-Charging-Characteristics
    pub const CHARGING_CHARACTERISTICS: u32 = 13;
    /// User-Equipment-Info
    pub const USER_EQUIPMENT_INFO: u32 = 458;
    /// User-Equipment-Info-Type
    pub const USER_EQUIPMENT_INFO_TYPE: u32 = 459;
    /// User-Equipment-Info-Value
    pub const USER_EQUIPMENT_INFO_VALUE: u32 = 460;
    /// Feature-List-ID
    pub const FEATURE_LIST_ID: u32 = 629;
    /// Feature-List
    pub const FEATURE_LIST: u32 = 630;
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
    /// 3GPP-RAT-Type
    pub const RAT_TYPE: u32 = 21;
    /// 3GPP-User-Location-Info
    pub const USER_LOCATION_INFO: u32 = 22;
    /// Called-Station-Id
    pub const CALLED_STATION_ID: u32 = 30;
    /// 3GPP-MS-TimeZone
    pub const MS_TIMEZONE: u32 = 23;
    /// Flows
    pub const FLOWS: u32 = 510;
    /// 3GPP-SGSN-MCC-MNC
    pub const SGSN_MCC_MNC: u32 = 18;
    /// Rating-Group
    pub const RATING_GROUP: u32 = 432;
}


/// Requested-Action values
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum RequestedAction {
    DirectDebiting = 0,
    RefundAccount = 1,
    CheckBalance = 2,
    PriceEnquiry = 3,
}

/// AoC-Request-Type values
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum AocRequestType {
    NotRequested = 0,
    Full = 1,
    CostOnly = 2,
    TariffOnly = 3,
}

/// Multiple-Services-Indicator values
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum MultipleServicesIndicator {
    NotSupported = 0,
    Supported = 1,
}

/// Reporting-Reason values
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ReportingReason {
    Threshold = 0,
    Qht = 1,
    Final = 2,
    QuotaExhausted = 3,
    ValidityTime = 4,
    OtherQuotaType = 5,
    RatingConditionChange = 6,
    ForcedReauthorisation = 7,
    PoolExhausted = 8,
    UnusedQuotaTimer = 9,
}

/// 3GPP-PDP-Type values
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum PdpType {
    Ipv4 = 0,
    Ppp = 1,
    Ipv6 = 2,
    Ipv4v6 = 3,
    NonIp = 4,
    Unstructured = 5,
    Ethernet = 6,
}

/// Final-Unit-Action values
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum FinalUnitAction {
    Terminate = 0,
    Redirect = 1,
    RestrictAccess = 2,
}

/// CC-Request-Type values (same as Gx)
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

/// 3GPP User Location Info Type
pub mod user_location_info_type {
    pub const CGI: u8 = 0;
    pub const SAI: u8 = 1;
    pub const RAI: u8 = 2;
    pub const TAI: u8 = 128;
    pub const ECGI: u8 = 129;
    pub const TAI_AND_ECGI: u8 = 130;
    pub const ENODEB_ID: u8 = 131;
    pub const TAI_AND_ENODEB_ID: u8 = 132;
    pub const EXT_ENODEB_ID: u8 = 133;
    pub const TAI_AND_EXT_ENODEB_ID: u8 = 134;
}

/// Gy Experimental Result Codes
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

/// Service unit for credit control
#[derive(Debug, Clone, Default)]
pub struct ServiceUnit {
    /// CC-Time present flag
    pub cc_time_present: bool,
    /// CC-Time value
    pub cc_time: u32,
    /// CC-Total-Octets present flag
    pub cc_total_octets_present: bool,
    /// CC-Total-Octets value
    pub cc_total_octets: u64,
    /// CC-Input-Octets present flag
    pub cc_input_octets_present: bool,
    /// CC-Input-Octets value
    pub cc_input_octets: u64,
    /// CC-Output-Octets present flag
    pub cc_output_octets_present: bool,
    /// CC-Output-Octets value
    pub cc_output_octets: u64,
}

/// Final unit indication
#[derive(Debug, Clone, Default)]
pub struct FinalUnit {
    /// Final action present flag
    pub cc_final_action_present: bool,
    /// Final action value
    pub cc_final_action: i32,
}

/// CCA (Credit-Control-Answer) specific data
#[derive(Debug, Clone, Default)]
pub struct CcaData {
    /// Validity time
    pub validity_time: u32,
    /// Time threshold
    pub time_threshold: u32,
    /// Volume threshold
    pub volume_threshold: u32,
    /// Granted service unit
    pub granted: ServiceUnit,
    /// Final unit indication
    pub final_unit: FinalUnit,
    /// Result code
    pub result_code: u32,
    /// Error
    pub err: Option<u32>,
}

/// Gy message
#[derive(Debug, Clone)]
pub struct GyMessage {
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
    /// CCA-specific data (for answers)
    pub cca: Option<CcaData>,
}

impl GyMessage {
    /// Create a new Gy message
    pub fn new(cmd_code: u16) -> Self {
        Self {
            cmd_code,
            result_code: 0,
            err: None,
            exp_err: None,
            cc_request_type: CcRequestType::InitialRequest,
            cca: None,
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
    let mut msg = DiameterMessage::new_request(cmd::CREDIT_CONTROL, GY_APPLICATION_ID);

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
        AvpData::Unsigned32(GY_APPLICATION_ID),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_ccr() {
        let msg = create_ccr(
            "session123",
            "smf.epc.mnc001.mcc001.3gppnetwork.org",
            "epc.mnc001.mcc001.3gppnetwork.org",
            "epc.mnc001.mcc001.3gppnetwork.org",
            CcRequestType::InitialRequest,
            0,
        );

        assert_eq!(msg.header.command_code, cmd::CREDIT_CONTROL);
        assert_eq!(msg.header.application_id, GY_APPLICATION_ID);
        assert!(msg.header.is_request());
    }

    #[test]
    fn test_service_unit_default() {
        let su = ServiceUnit::default();
        assert!(!su.cc_time_present);
        assert_eq!(su.cc_time, 0);
        assert!(!su.cc_total_octets_present);
    }
}
