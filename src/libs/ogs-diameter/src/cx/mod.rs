//! Cx Interface - I-CSCF/S-CSCF <-> HSS (3GPP TS 29.228/29.229)
//!
//! The Cx interface is used for IMS Registration:
//! - User-Authorization-Request/Answer (UAR/UAA)
//! - Multimedia-Auth-Request/Answer (MAR/MAA)
//! - Server-Assignment-Request/Answer (SAR/SAA)
//! - Location-Info-Request/Answer (LIR/LIA)
//! - Registration-Termination-Request/Answer (RTR/RTA)
//! - Push-Profile-Request/Answer (PPR/PPA)

use crate::avp::{Avp, AvpData};
use crate::common::avp_code;
use crate::message::DiameterMessage;
use crate::OGS_3GPP_VENDOR_ID;

/// Cx Application ID (3GPP TS 29.229)
pub const CX_APPLICATION_ID: u32 = 16777216;

/// Cx Command Codes
pub mod cmd {
    /// User-Authorization-Request/Answer
    pub const USER_AUTHORIZATION: u32 = 300;
    /// Server-Assignment-Request/Answer
    pub const SERVER_ASSIGNMENT: u32 = 301;
    /// Location-Info-Request/Answer
    pub const LOCATION_INFO: u32 = 302;
    /// Multimedia-Auth-Request/Answer
    pub const MULTIMEDIA_AUTH: u32 = 303;
    /// Registration-Termination-Request/Answer
    pub const REGISTRATION_TERMINATION: u32 = 304;
    /// Push-Profile-Request/Answer
    pub const PUSH_PROFILE: u32 = 305;
}

/// Cx AVP Codes
pub mod avp {
    /// Public-Identity
    pub const PUBLIC_IDENTITY: u32 = 601;
    /// Server-Name
    pub const SERVER_NAME: u32 = 602;
    /// SIP-Number-Auth-Items
    pub const SIP_NUMBER_AUTH_ITEMS: u32 = 607;
    /// SIP-Item-Number
    pub const SIP_ITEM_NUMBER: u32 = 613;
    /// SIP-Auth-Data-Item
    pub const SIP_AUTH_DATA_ITEM: u32 = 612;
    /// SIP-Authentication-Scheme
    pub const SIP_AUTHENTICATION_SCHEME: u32 = 608;
    /// SIP-Authenticate
    pub const SIP_AUTHENTICATE: u32 = 609;
    /// SIP-Authorization
    pub const SIP_AUTHORIZATION: u32 = 610;
    /// Confidentiality-Key
    pub const CONFIDENTIALITY_KEY: u32 = 625;
    /// Integrity-Key
    pub const INTEGRITY_KEY: u32 = 626;
    /// Server-Assignment-Type
    pub const SERVER_ASSIGNMENT_TYPE: u32 = 614;
    /// User-Data-Already-Available
    pub const USER_DATA_ALREADY_AVAILABLE: u32 = 624;
    /// User-Data
    pub const USER_DATA: u32 = 606;
    /// Charging-Information
    pub const CHARGING_INFORMATION: u32 = 618;
    /// Primary-Event-Charging-Function-Name
    pub const PRIMARY_EVENT_CHARGING_FUNCTION_NAME: u32 = 619;
    /// Secondary-Event-Charging-Function-Name
    pub const SECONDARY_EVENT_CHARGING_FUNCTION_NAME: u32 = 620;
    /// Primary-Charging-Collection-Function-Name
    pub const PRIMARY_CHARGING_COLLECTION_FUNCTION_NAME: u32 = 621;
    /// Secondary-Charging-Collection-Function-Name
    pub const SECONDARY_CHARGING_COLLECTION_FUNCTION_NAME: u32 = 622;
    /// Visited-Network-Identifier
    pub const VISITED_NETWORK_IDENTIFIER: u32 = 600;
    /// User-Authorization-Type
    pub const USER_AUTHORIZATION_TYPE: u32 = 623;
    /// Deregistration-Reason
    pub const DEREGISTRATION_REASON: u32 = 615;
    /// Reason-Code
    pub const REASON_CODE: u32 = 616;
    /// Reason-Info
    pub const REASON_INFO: u32 = 617;
    /// Associated-Identities
    pub const ASSOCIATED_IDENTITIES: u32 = 632;
    /// Wildcarded-Public-Identity
    pub const WILDCARDED_PUBLIC_IDENTITY: u32 = 634;
}

/// Authentication schemes
pub mod auth_scheme {
    pub const IMS_AKA: &str = "Digest-AKAv1-MD5";
    pub const SIP_DIGEST: &str = "SIP Digest";
    pub const NASS_BUNDLED: &str = "NASS-Bundled";
    pub const GPRS_IMS_BUNDLED: &str = "Early-IMS-Security";
    pub const UNKNOWN: &str = "Unknown";
}

/// Server-Assignment-Type values
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

/// User-Data-Already-Available values
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum UserDataAlreadyAvailable {
    NotAvailable = 0,
    AlreadyAvailable = 1,
}

/// Cx Experimental Result Codes
pub mod exp_result {
    /// First Registration
    pub const FIRST_REGISTRATION: u32 = 2001;
    /// Subsequent Registration
    pub const SUBSEQUENT_REGISTRATION: u32 = 2002;
    /// Unregistered Service
    pub const UNREGISTERED_SERVICE: u32 = 2003;
    /// Server Name Not Stored
    pub const SERVER_NAME_NOT_STORED: u32 = 2004;
    /// Error: User Unknown
    pub const ERROR_USER_UNKNOWN: u32 = 5001;
    /// Error: Identities Don't Match
    pub const ERROR_IDENTITIES_DONT_MATCH: u32 = 5002;
    /// Error: Identity Not Registered
    pub const ERROR_IDENTITY_NOT_REGISTERED: u32 = 5003;
    /// Error: Roaming Not Allowed
    pub const ERROR_ROAMING_NOT_ALLOWED: u32 = 5004;
    /// Error: Identity Already Registered
    pub const ERROR_IDENTITY_ALREADY_REGISTERED: u32 = 5005;
    /// Error: Auth Scheme Not Supported
    pub const ERROR_AUTH_SCHEME_NOT_SUPPORTED: u32 = 5006;
    /// Error: In Assignment Type
    pub const ERROR_IN_ASSIGNMENT_TYPE: u32 = 5007;
    /// Error: Too Much Data
    pub const ERROR_TOO_MUCH_DATA: u32 = 5008;
    /// Error: Not Supported User Data
    pub const ERROR_NOT_SUPPORTED_USER_DATA: u32 = 5009;
    /// Error: Feature Unsupported
    pub const ERROR_FEATURE_UNSUPPORTED: u32 = 5011;
    /// Error: Serving Node Feature Unsupported
    pub const ERROR_SERVING_NODE_FEATURE_UNSUPPORTED: u32 = 5012;
}

/// XML element strings for IMS subscription data
pub mod xml {
    pub const VERSION: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>";
    pub const IMS_SUBSCRIPTION_S: &str = "<IMSSubscription>";
    pub const IMS_SUBSCRIPTION_E: &str = "</IMSSubscription>";
    pub const PRIVATE_ID_S: &str = "<PrivateID>";
    pub const PRIVATE_ID_E: &str = "</PrivateID>";
    pub const SERVICE_PROFILE_S: &str = "<ServiceProfile>";
    pub const SERVICE_PROFILE_E: &str = "</ServiceProfile>";
    pub const PUBLIC_ID_S: &str = "<PublicIdentity>";
    pub const PUBLIC_ID_E: &str = "</PublicIdentity>";
    pub const BARRING_INDICATION_S: &str = "<BarringIndication>";
    pub const BARRING_INDICATION_E: &str = "</BarringIndication>";
    pub const IDENTITY_S: &str = "<Identity>";
    pub const IDENTITY_E: &str = "</Identity>";
    pub const IDENTITY_TYPE_S: &str = "<IdentityType>";
    pub const IDENTITY_TYPE_E: &str = "</IdentityType>";
    pub const WILDCARDED_PSI_S: &str = "<WildcardedPSI>";
    pub const WILDCARDED_PSI_E: &str = "</WildcardedPSI>";
    pub const DISPLAY_NAME_S: &str = "<DisplayName>";
    pub const DISPLAY_NAME_E: &str = "</DisplayName>";
    pub const IFC_S: &str = "<InitialFilterCriteria>";
    pub const IFC_E: &str = "</InitialFilterCriteria>";
    pub const PRIORITY_S: &str = "<Priority>";
    pub const PRIORITY_E: &str = "</Priority>";
    pub const TP_S: &str = "<TriggerPoint>";
    pub const TP_E: &str = "</TriggerPoint>";
    pub const CNF_S: &str = "<ConditionTypeCNF>";
    pub const CNF_E: &str = "</ConditionTypeCNF>";
    pub const SPT_S: &str = "<SPT>";
    pub const SPT_E: &str = "</SPT>";
    pub const CONDITION_NEGATED_S: &str = "<ConditionNegated>";
    pub const CONDITION_NEGATED_E: &str = "</ConditionNegated>";
    pub const GROUP_S: &str = "<Group>";
    pub const GROUP_E: &str = "</Group>";
    pub const REQ_URI_S: &str = "<RequestURI>";
    pub const REQ_URI_E: &str = "</RequestURI>";
    pub const METHOD_S: &str = "<Method>";
    pub const METHOD_E: &str = "</Method>";
    pub const SIP_HDR_S: &str = "<SIPHeader>";
    pub const SIP_HDR_E: &str = "</SIPHeader>";
    pub const SESSION_CASE_S: &str = "<SessionCase>";
    pub const SESSION_CASE_E: &str = "</SessionCase>";
    pub const SESSION_DESC_S: &str = "<SessionDescription>";
    pub const SESSION_DESC_E: &str = "</SessionDescription>";
    pub const REGISTRATION_TYPE_S: &str = "<RegistrationType>";
    pub const REGISTRATION_TYPE_E: &str = "</RegistrationType>";
    pub const HEADER_S: &str = "<Header>";
    pub const HEADER_E: &str = "</Header>";
    pub const CONTENT_S: &str = "<Content>";
    pub const CONTENT_E: &str = "</Content>";
    pub const LINE_S: &str = "<Line>";
    pub const LINE_E: &str = "</Line>";
    pub const APP_SERVER_S: &str = "<ApplicationServer>";
    pub const APP_SERVER_E: &str = "</ApplicationServer>";
    pub const SERVER_NAME_S: &str = "<ServerName>";
    pub const SERVER_NAME_E: &str = "</ServerName>";
    pub const DEFAULT_HANDLING_S: &str = "<DefaultHandling>";
    pub const DEFAULT_HANDLING_E: &str = "</DefaultHandling>";
    pub const SERVICE_INFO_S: &str = "<ServiceInfo>";
    pub const SERVICE_INFO_E: &str = "</ServiceInfo>";
    pub const INCLUDE_REGISTER_REQUEST: &str = "<IncludeRegisterRequest/>";
    pub const INCLUDE_REGISTER_RESPONSE: &str = "<IncludeRegisterResponse/>";
    pub const PROFILE_PART_IND_S: &str = "<ProfilePartIndicator>";
    pub const PROFILE_PART_IND_E: &str = "</ProfilePartIndicator>";
    pub const CN_SERVICES_AUTH_S: &str = "<CoreNetworkServicesAuthorization>";
    pub const CN_SERVICES_AUTH_E: &str = "</CoreNetworkServicesAuthorization>";
    pub const SUBS_MEDIA_PROFILE_ID_S: &str = "<SubscribedMediaProfileId>";
    pub const SUBS_MEDIA_PROFILE_ID_E: &str = "</SubscribedMediaProfileId>";
    pub const SHARED_IFC_SET_ID_S: &str = "<SharedIFCSetID>";
    pub const SHARED_IFC_SET_ID_E: &str = "</SharedIFCSetID>";
    pub const EXTENSION_S: &str = "<Extension>";
    pub const EXTENSION_E: &str = "</Extension>";
}

/// Create a User-Authorization-Request (UAR)
pub fn create_uar(
    session_id: &str,
    origin_host: &str,
    origin_realm: &str,
    destination_realm: &str,
    public_identity: &str,
    visited_network_id: &str,
) -> DiameterMessage {
    let mut msg = DiameterMessage::new_request(cmd::USER_AUTHORIZATION, CX_APPLICATION_ID);

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
            AvpData::Unsigned32(CX_APPLICATION_ID),
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

    // Public-Identity
    msg.add_avp(Avp::vendor_mandatory(
        avp::PUBLIC_IDENTITY,
        OGS_3GPP_VENDOR_ID,
        AvpData::Utf8String(public_identity.to_string()),
    ));

    // Visited-Network-Identifier
    msg.add_avp(Avp::vendor_mandatory(
        avp::VISITED_NETWORK_IDENTIFIER,
        OGS_3GPP_VENDOR_ID,
        AvpData::OctetString(bytes::Bytes::copy_from_slice(visited_network_id.as_bytes())),
    ));

    msg
}

/// Create a Multimedia-Auth-Request (MAR)
pub fn create_mar(
    session_id: &str,
    origin_host: &str,
    origin_realm: &str,
    destination_realm: &str,
    public_identity: &str,
    user_name: &str,
    num_auth_items: u32,
    auth_scheme: &str,
) -> DiameterMessage {
    let mut msg = DiameterMessage::new_request(cmd::MULTIMEDIA_AUTH, CX_APPLICATION_ID);

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
            AvpData::Unsigned32(CX_APPLICATION_ID),
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

    // User-Name
    msg.add_avp(Avp::mandatory(
        avp_code::USER_NAME,
        AvpData::Utf8String(user_name.to_string()),
    ));

    // Public-Identity
    msg.add_avp(Avp::vendor_mandatory(
        avp::PUBLIC_IDENTITY,
        OGS_3GPP_VENDOR_ID,
        AvpData::Utf8String(public_identity.to_string()),
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

    // Server-Name
    msg.add_avp(Avp::vendor_mandatory(
        avp::SERVER_NAME,
        OGS_3GPP_VENDOR_ID,
        AvpData::Utf8String(format!("sip:{}", origin_host)),
    ));

    msg
}

/// Create a Server-Assignment-Request (SAR)
pub fn create_sar(
    session_id: &str,
    origin_host: &str,
    origin_realm: &str,
    destination_realm: &str,
    public_identity: &str,
    server_name: &str,
    assignment_type: ServerAssignmentType,
) -> DiameterMessage {
    let mut msg = DiameterMessage::new_request(cmd::SERVER_ASSIGNMENT, CX_APPLICATION_ID);

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
            AvpData::Unsigned32(CX_APPLICATION_ID),
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

    // Public-Identity
    msg.add_avp(Avp::vendor_mandatory(
        avp::PUBLIC_IDENTITY,
        OGS_3GPP_VENDOR_ID,
        AvpData::Utf8String(public_identity.to_string()),
    ));

    // Server-Name
    msg.add_avp(Avp::vendor_mandatory(
        avp::SERVER_NAME,
        OGS_3GPP_VENDOR_ID,
        AvpData::Utf8String(server_name.to_string()),
    ));

    // Server-Assignment-Type
    msg.add_avp(Avp::vendor_mandatory(
        avp::SERVER_ASSIGNMENT_TYPE,
        OGS_3GPP_VENDOR_ID,
        AvpData::Enumerated(assignment_type as i32),
    ));

    // User-Data-Already-Available
    msg.add_avp(Avp::vendor_mandatory(
        avp::USER_DATA_ALREADY_AVAILABLE,
        OGS_3GPP_VENDOR_ID,
        AvpData::Enumerated(UserDataAlreadyAvailable::NotAvailable as i32),
    ));

    msg
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_uar() {
        let msg = create_uar(
            "session123",
            "icscf.ims.mnc001.mcc001.3gppnetwork.org",
            "ims.mnc001.mcc001.3gppnetwork.org",
            "ims.mnc001.mcc001.3gppnetwork.org",
            "sip:user@ims.mnc001.mcc001.3gppnetwork.org",
            "ims.mnc001.mcc001.3gppnetwork.org",
        );

        assert_eq!(msg.header.command_code, cmd::USER_AUTHORIZATION);
        assert_eq!(msg.header.application_id, CX_APPLICATION_ID);
        assert!(msg.header.is_request());
    }

    #[test]
    fn test_create_mar() {
        let msg = create_mar(
            "session123",
            "scscf.ims.mnc001.mcc001.3gppnetwork.org",
            "ims.mnc001.mcc001.3gppnetwork.org",
            "ims.mnc001.mcc001.3gppnetwork.org",
            "sip:user@ims.mnc001.mcc001.3gppnetwork.org",
            "user@ims.mnc001.mcc001.3gppnetwork.org",
            1,
            auth_scheme::IMS_AKA,
        );

        assert_eq!(msg.header.command_code, cmd::MULTIMEDIA_AUTH);
        assert_eq!(msg.header.application_id, CX_APPLICATION_ID);
    }

    #[test]
    fn test_create_sar() {
        let msg = create_sar(
            "session123",
            "scscf.ims.mnc001.mcc001.3gppnetwork.org",
            "ims.mnc001.mcc001.3gppnetwork.org",
            "ims.mnc001.mcc001.3gppnetwork.org",
            "sip:user@ims.mnc001.mcc001.3gppnetwork.org",
            "sip:scscf.ims.mnc001.mcc001.3gppnetwork.org",
            ServerAssignmentType::Registration,
        );

        assert_eq!(msg.header.command_code, cmd::SERVER_ASSIGNMENT);
        assert_eq!(msg.header.application_id, CX_APPLICATION_ID);
    }
}
