//! Rx Interface - AF <-> PCRF (3GPP TS 29.214)
//!
//! The Rx interface is used for Application Function interaction:
//! - AA-Request/Answer (AAR/AAA)
//! - Abort-Session-Request/Answer (ASR/ASA)
//! - Session-Termination-Request/Answer (STR/STA)
//! - Re-Auth-Request/Answer (RAR/RAA)

use crate::avp::{Avp, AvpData};
use crate::common::avp_code;
use crate::message::DiameterMessage;
use crate::OGS_3GPP_VENDOR_ID;

/// Rx Application ID (3GPP TS 29.214)
pub const RX_APPLICATION_ID: u32 = 16777236;

/// Rx Command Codes
pub mod cmd {
    /// AA-Request/Answer
    pub const AA: u32 = 265;
    /// Session-Termination-Request/Answer
    pub const SESSION_TERMINATION: u32 = 275;
    /// Abort-Session-Request/Answer
    pub const ABORT_SESSION: u32 = 274;
    /// Re-Auth-Request/Answer
    pub const RE_AUTH: u32 = 258;
}

/// Rx AVP Codes
pub mod avp {
    /// Subscription-Id
    pub const SUBSCRIPTION_ID: u32 = 443;
    /// Specific-Action
    pub const SPECIFIC_ACTION: u32 = 513;
    /// Media-Component-Description
    pub const MEDIA_COMPONENT_DESCRIPTION: u32 = 517;
    /// Media-Type
    pub const MEDIA_TYPE: u32 = 520;
    /// Max-Requested-Bandwidth-DL
    pub const MAX_REQUESTED_BANDWIDTH_DL: u32 = 515;
    /// Max-Requested-Bandwidth-UL
    pub const MAX_REQUESTED_BANDWIDTH_UL: u32 = 516;
    /// RR-Bandwidth
    pub const RR_BANDWIDTH: u32 = 521;
    /// RS-Bandwidth
    pub const RS_BANDWIDTH: u32 = 522;
    /// Min-Requested-Bandwidth-DL
    pub const MIN_REQUESTED_BANDWIDTH_DL: u32 = 534;
    /// Min-Requested-Bandwidth-UL
    pub const MIN_REQUESTED_BANDWIDTH_UL: u32 = 535;
    /// Media-Component-Number
    pub const MEDIA_COMPONENT_NUMBER: u32 = 518;
    /// Media-Sub-Component
    pub const MEDIA_SUB_COMPONENT: u32 = 519;
    /// Flow-Description
    pub const FLOW_DESCRIPTION: u32 = 507;
    /// Flow-Number
    pub const FLOW_NUMBER: u32 = 509;
    /// Flow-Status
    pub const FLOW_STATUS: u32 = 511;
    /// Flow-Usage
    pub const FLOW_USAGE: u32 = 512;
    /// Subscription-Id-Type
    pub const SUBSCRIPTION_ID_TYPE: u32 = 450;
    /// Subscription-Id-Data
    pub const SUBSCRIPTION_ID_DATA: u32 = 444;
    /// Reservation-Priority
    pub const RESERVATION_PRIORITY: u32 = 458;
    /// Framed-IP-Address
    pub const FRAMED_IP_ADDRESS: u32 = 8;
    /// Framed-IPv6-Prefix
    pub const FRAMED_IPV6_PREFIX: u32 = 97;
    /// IP-CAN-Type
    pub const IP_CAN_TYPE: u32 = 1027;
    /// Abort-Cause
    pub const ABORT_CAUSE: u32 = 500;
    /// AF-Application-Identifier
    pub const AF_APPLICATION_IDENTIFIER: u32 = 504;
    /// Codec-Data
    pub const CODEC_DATA: u32 = 524;
}

/// Media-Type values
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum MediaType {
    Audio = 0,
    Video = 1,
    Data = 2,
    Application = 3,
    Control = 4,
    Text = 5,
    Message = 6,
    Other = 0xFFFFFFFF,
}

/// Flow-Status values
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum FlowStatus {
    EnabledUplink = 0,
    EnabledDownlink = 1,
    Enabled = 2,
    Disabled = 3,
}

/// Flow-Usage values
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum FlowUsage {
    NoInformation = 0,
    Rtcp = 1,
    AfSignalling = 2,
}

/// Subscription-Id-Type values
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum SubscriptionIdType {
    EndUserE164 = 0,
    EndUserImsi = 1,
    EndUserSipUri = 2,
    EndUserNai = 3,
}

/// Specific-Action values
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum SpecificAction {
    ChargingCorrelationExchange = 1,
    IndicationOfLossOfBearer = 2,
    IndicationOfRecoveryOfBearer = 3,
    IndicationOfReleaseOfBearer = 4,
    IndicationOfEstablishmentOfBearer = 5,
    IpCanChange = 6,
    AccessNetworkInfoReport = 12,
}

/// IP-CAN-Type values
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

/// Abort-Cause values
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum AbortCause {
    BearerReleased = 0,
    InsufficientServerResources = 1,
    InsufficientBearerResources = 2,
    PsToCsHandover = 3,
    SponsoredDataConnectivityDisallowed = 4,
}

/// Rx Experimental Result Codes
pub mod exp_result {
    pub const INVALID_SERVICE_INFORMATION: u32 = 5061;
    pub const FILTER_RESTRICTIONS: u32 = 5062;
    pub const REQUESTED_SERVICE_NOT_AUTHORIZED: u32 = 5063;
    pub const DUPLICATED_AF_SESSION: u32 = 5064;
    pub const IP_CAN_SESSION_NOT_AVAILABLE: u32 = 5065;
    pub const UNAUTHORIZED_NON_EMERGENCY_SESSION: u32 = 5066;
    pub const UNAUTHORIZED_SPONSORED_DATA_CONNECTIVITY: u32 = 5067;
    pub const TEMPORARY_NETWORK_FAILURE: u32 = 5068;
}

/// Rx message
#[derive(Debug, Clone)]
pub struct RxMessage {
    /// Command code
    pub cmd_code: u16,
    /// Result code
    pub result_code: u32,
    // Note: ims_data would be a complex type from ogs-core
}

impl RxMessage {
    /// Create a new Rx message
    pub fn new(cmd_code: u16) -> Self {
        Self {
            cmd_code,
            result_code: 0,
        }
    }
}

/// Create an AA-Request (AAR)
pub fn create_aar(
    session_id: &str,
    origin_host: &str,
    origin_realm: &str,
    destination_realm: &str,
) -> DiameterMessage {
    let mut msg = DiameterMessage::new_request(cmd::AA, RX_APPLICATION_ID);

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
        AvpData::Unsigned32(RX_APPLICATION_ID),
    ));

    msg
}

/// Create a Session-Termination-Request (STR)
pub fn create_str(
    session_id: &str,
    origin_host: &str,
    origin_realm: &str,
    destination_realm: &str,
    termination_cause: u32,
) -> DiameterMessage {
    let mut msg = DiameterMessage::new_request(cmd::SESSION_TERMINATION, RX_APPLICATION_ID);

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
        AvpData::Unsigned32(RX_APPLICATION_ID),
    ));

    // Termination-Cause
    msg.add_avp(Avp::mandatory(
        avp_code::TERMINATION_CAUSE,
        AvpData::Enumerated(termination_cause as i32),
    ));

    msg
}

/// Add Subscription-Id AVP to message
pub fn add_subscription_id(
    msg: &mut DiameterMessage,
    id_type: SubscriptionIdType,
    id_data: &str,
) {
    let grouped = vec![
        Avp::mandatory(
            avp::SUBSCRIPTION_ID_TYPE,
            AvpData::Enumerated(id_type as i32),
        ),
        Avp::mandatory(
            avp::SUBSCRIPTION_ID_DATA,
            AvpData::Utf8String(id_data.to_string()),
        ),
    ];

    msg.add_avp(Avp::mandatory(
        avp::SUBSCRIPTION_ID,
        AvpData::Grouped(grouped),
    ));
}

/// Add Specific-Action AVP to message
pub fn add_specific_action(msg: &mut DiameterMessage, action: SpecificAction) {
    msg.add_avp(Avp::vendor_mandatory(
        avp::SPECIFIC_ACTION,
        OGS_3GPP_VENDOR_ID,
        AvpData::Enumerated(action as i32),
    ));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_aar() {
        let msg = create_aar(
            "session123",
            "af.ims.mnc001.mcc001.3gppnetwork.org",
            "ims.mnc001.mcc001.3gppnetwork.org",
            "epc.mnc001.mcc001.3gppnetwork.org",
        );

        assert_eq!(msg.header.command_code, cmd::AA);
        assert_eq!(msg.header.application_id, RX_APPLICATION_ID);
        assert!(msg.header.is_request());
    }

    #[test]
    fn test_create_str() {
        let msg = create_str(
            "session123",
            "af.ims.mnc001.mcc001.3gppnetwork.org",
            "ims.mnc001.mcc001.3gppnetwork.org",
            "epc.mnc001.mcc001.3gppnetwork.org",
            1, // DIAMETER_LOGOUT
        );

        assert_eq!(msg.header.command_code, cmd::SESSION_TERMINATION);
        assert_eq!(msg.header.application_id, RX_APPLICATION_ID);
    }
}
