//! SWx Interface - 3GPP AAA Server <-> HSS (3GPP TS 29.273)
//!
//! The SWx interface is used for Non-3GPP Access authentication:
//! - Multimedia-Auth-Request/Answer (MAR/MAA)
//! - Server-Assignment-Request/Answer (SAR/SAA)
//! - Registration-Termination-Request/Answer (RTR/RTA)
//! - Push-Profile-Request/Answer (PPR/PPA)

use crate::avp::{Avp, AvpData};
use crate::common::avp_code;
use crate::message::DiameterMessage;
use crate::OGS_3GPP_VENDOR_ID;

/// SWx Application ID (3GPP TS 29.273)
pub const SWX_APPLICATION_ID: u32 = 16777265;

/// SWx Command Codes (same as Cx for most)
pub mod cmd {
    /// Multimedia-Auth-Request/Answer
    pub const MULTIMEDIA_AUTH: u32 = 303;
    /// Server-Assignment-Request/Answer
    pub const SERVER_ASSIGNMENT: u32 = 301;
    /// Registration-Termination-Request/Answer
    pub const REGISTRATION_TERMINATION: u32 = 304;
    /// Push-Profile-Request/Answer
    pub const PUSH_PROFILE: u32 = 305;
}

/// SWx AVP Codes
pub mod avp {
    /// Non-3GPP-User-Data
    pub const NON_3GPP_USER_DATA: u32 = 1500;
    /// Non-3GPP-IP-Access
    pub const NON_3GPP_IP_ACCESS: u32 = 1501;
    /// Non-3GPP-IP-Access-APN
    pub const NON_3GPP_IP_ACCESS_APN: u32 = 1502;
    /// AN-Trusted
    pub const AN_TRUSTED: u32 = 1503;
    /// ANID
    pub const ANID: u32 = 1504;
    /// Trace-Info
    pub const TRACE_INFO: u32 = 1505;
    /// MIP6-Feature-Vector
    pub const MIP6_FEATURE_VECTOR: u32 = 124;
    /// MIP-Home-Agent-Address
    pub const MIP_HOME_AGENT_ADDRESS: u32 = 334;
    /// MIP-Home-Agent-Host
    pub const MIP_HOME_AGENT_HOST: u32 = 348;
    /// MIP6-Agent-Info
    pub const MIP6_AGENT_INFO: u32 = 486;
    /// 3GPP-AAA-Server-Name
    pub const AAA_SERVER_NAME: u32 = 318;
    /// SIP-Auth-Data-Item (from Cx)
    pub const SIP_AUTH_DATA_ITEM: u32 = 612;
    /// SIP-Number-Auth-Items (from Cx)
    pub const SIP_NUMBER_AUTH_ITEMS: u32 = 607;
    /// SIP-Authentication-Scheme (from Cx)
    pub const SIP_AUTHENTICATION_SCHEME: u32 = 608;
    /// SIP-Authenticate (from Cx)
    pub const SIP_AUTHENTICATE: u32 = 609;
    /// SIP-Authorization (from Cx)
    pub const SIP_AUTHORIZATION: u32 = 610;
    /// Confidentiality-Key (from Cx)
    pub const CONFIDENTIALITY_KEY: u32 = 625;
    /// Integrity-Key (from Cx)
    pub const INTEGRITY_KEY: u32 = 626;
    /// Server-Assignment-Type (from Cx)
    pub const SERVER_ASSIGNMENT_TYPE: u32 = 614;
    /// Service-Selection
    pub const SERVICE_SELECTION: u32 = 493;
    /// Context-Identifier
    pub const CONTEXT_IDENTIFIER: u32 = 1423;
    /// Subscription-Data (from S6a)
    pub const SUBSCRIPTION_DATA: u32 = 1400;
    /// APN-Configuration (from S6a)
    pub const APN_CONFIGURATION: u32 = 1430;
    /// Deregistration-Reason (from Cx)
    pub const DEREGISTRATION_REASON: u32 = 615;
    /// Reason-Code (from Cx)
    pub const REASON_CODE: u32 = 616;
    /// Reason-Info (from Cx)
    pub const REASON_INFO: u32 = 617;
}

/// Authentication schemes for SWx
pub mod auth_scheme {
    pub const EAP_AKA: &str = "EAP-AKA";
    pub const EAP_AKA_PRIME: &str = "EAP-AKA'";
}

/// Non-3GPP-IP-Access values
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum Non3GppIpAccess {
    SubscriptionAllowed = 0,
    SubscriptionBarred = 1,
}

/// Non-3GPP-IP-Access-APN values
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum Non3GppIpAccessApn {
    ApnsEnable = 0,
    ApnsDisable = 1,
}

/// AN-Trusted values
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum AnTrusted {
    Trusted = 0,
    Untrusted = 1,
}

/// Server-Assignment-Type values (same as Cx)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ServerAssignmentType {
    NoAssignment = 0,
    Registration = 1,
    ReRegistration = 2,
    UnregisteredUser = 3,
    TimeoutDeregistration = 4,
    UserDeregistration = 5,
    TimeoutDeregistrationStoreServerName = 6,
    UserDeregistrationStoreServerName = 7,
    AdministrativeDeregistration = 8,
    AuthenticationFailure = 9,
    AuthenticationTimeout = 10,
    DeregistrationTooMuchData = 11,
    AaaUserDataRequest = 12,
    PgwUpdate = 13,
    Restoration = 14,
}

/// Reason-Code values for deregistration
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ReasonCode {
    PermanentTermination = 0,
    NewServerAssigned = 1,
    ServerChange = 2,
    RemoveScscf = 3,
}

/// Create a Multimedia-Auth-Request (MAR) for SWx
pub fn create_mar(
    session_id: &str,
    origin_host: &str,
    origin_realm: &str,
    destination_realm: &str,
    user_name: &str,
    num_auth_items: u32,
    auth_scheme: &str,
) -> DiameterMessage {
    let mut msg = DiameterMessage::new_request(cmd::MULTIMEDIA_AUTH, SWX_APPLICATION_ID);

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

    // Vendor-Specific-Application-Id
    let vsai = vec![
        Avp::mandatory(avp_code::VENDOR_ID, AvpData::Unsigned32(OGS_3GPP_VENDOR_ID)),
        Avp::mandatory(
            avp_code::AUTH_APPLICATION_ID,
            AvpData::Unsigned32(SWX_APPLICATION_ID),
        ),
    ];
    msg.add_avp(Avp::mandatory(
        avp_code::VENDOR_SPECIFIC_APPLICATION_ID,
        AvpData::Grouped(vsai),
    ));

    // Auth-Session-State (NO_STATE_MAINTAINED)
    msg.add_avp(Avp::mandatory(
        avp_code::AUTH_SESSION_STATE,
        AvpData::Enumerated(1),
    ));

    // User-Name (IMSI)
    msg.add_avp(Avp::mandatory(
        avp_code::USER_NAME,
        AvpData::Utf8String(user_name.to_string()),
    ));

    // SIP-Number-Auth-Items
    msg.add_avp(Avp::vendor_mandatory(
        avp::SIP_NUMBER_AUTH_ITEMS,
        OGS_3GPP_VENDOR_ID,
        AvpData::Unsigned32(num_auth_items),
    ));

    // SIP-Auth-Data-Item
    let auth_data = vec![Avp::vendor_mandatory(
        avp::SIP_AUTHENTICATION_SCHEME,
        OGS_3GPP_VENDOR_ID,
        AvpData::Utf8String(auth_scheme.to_string()),
    )];
    msg.add_avp(Avp::vendor_mandatory(
        avp::SIP_AUTH_DATA_ITEM,
        OGS_3GPP_VENDOR_ID,
        AvpData::Grouped(auth_data),
    ));

    msg
}

/// Create a Server-Assignment-Request (SAR) for SWx
pub fn create_sar(
    session_id: &str,
    origin_host: &str,
    origin_realm: &str,
    destination_realm: &str,
    user_name: &str,
    server_name: &str,
    assignment_type: ServerAssignmentType,
) -> DiameterMessage {
    let mut msg = DiameterMessage::new_request(cmd::SERVER_ASSIGNMENT, SWX_APPLICATION_ID);

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

    // Vendor-Specific-Application-Id
    let vsai = vec![
        Avp::mandatory(avp_code::VENDOR_ID, AvpData::Unsigned32(OGS_3GPP_VENDOR_ID)),
        Avp::mandatory(
            avp_code::AUTH_APPLICATION_ID,
            AvpData::Unsigned32(SWX_APPLICATION_ID),
        ),
    ];
    msg.add_avp(Avp::mandatory(
        avp_code::VENDOR_SPECIFIC_APPLICATION_ID,
        AvpData::Grouped(vsai),
    ));

    // Auth-Session-State (NO_STATE_MAINTAINED)
    msg.add_avp(Avp::mandatory(
        avp_code::AUTH_SESSION_STATE,
        AvpData::Enumerated(1),
    ));

    // User-Name (IMSI)
    msg.add_avp(Avp::mandatory(
        avp_code::USER_NAME,
        AvpData::Utf8String(user_name.to_string()),
    ));

    // 3GPP-AAA-Server-Name
    msg.add_avp(Avp::vendor_mandatory(
        avp::AAA_SERVER_NAME,
        OGS_3GPP_VENDOR_ID,
        AvpData::DiameterIdentity(server_name.to_string()),
    ));

    // Server-Assignment-Type
    msg.add_avp(Avp::vendor_mandatory(
        avp::SERVER_ASSIGNMENT_TYPE,
        OGS_3GPP_VENDOR_ID,
        AvpData::Enumerated(assignment_type as i32),
    ));

    msg
}

/// Add Service-Selection (APN) AVP to message
pub fn add_service_selection(msg: &mut DiameterMessage, apn: &str) {
    msg.add_avp(Avp::mandatory(
        avp::SERVICE_SELECTION,
        AvpData::Utf8String(apn.to_string()),
    ));
}

/// Add AN-Trusted AVP to message
pub fn add_an_trusted(msg: &mut DiameterMessage, trusted: AnTrusted) {
    msg.add_avp(Avp::vendor_mandatory(
        avp::AN_TRUSTED,
        OGS_3GPP_VENDOR_ID,
        AvpData::Enumerated(trusted as i32),
    ));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_mar() {
        let msg = create_mar(
            "session123",
            "aaa.epc.mnc001.mcc001.3gppnetwork.org",
            "epc.mnc001.mcc001.3gppnetwork.org",
            "epc.mnc001.mcc001.3gppnetwork.org",
            "001010123456789",
            1,
            auth_scheme::EAP_AKA_PRIME,
        );

        assert_eq!(msg.header.command_code, cmd::MULTIMEDIA_AUTH);
        assert_eq!(msg.header.application_id, SWX_APPLICATION_ID);
        assert!(msg.header.is_request());
    }

    #[test]
    fn test_create_sar() {
        let msg = create_sar(
            "session123",
            "aaa.epc.mnc001.mcc001.3gppnetwork.org",
            "epc.mnc001.mcc001.3gppnetwork.org",
            "epc.mnc001.mcc001.3gppnetwork.org",
            "001010123456789",
            "aaa.epc.mnc001.mcc001.3gppnetwork.org",
            ServerAssignmentType::Registration,
        );

        assert_eq!(msg.header.command_code, cmd::SERVER_ASSIGNMENT);
        assert_eq!(msg.header.application_id, SWX_APPLICATION_ID);
    }

    #[test]
    fn test_an_trusted_values() {
        assert_eq!(AnTrusted::Trusted as u32, 0);
        assert_eq!(AnTrusted::Untrusted as u32, 1);
    }
}
