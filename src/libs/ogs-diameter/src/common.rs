//! Common Diameter types and constants

use crate::OGS_3GPP_VENDOR_ID;

/// AVP codes for common Diameter AVPs
pub mod avp_code {
    // RFC 6733 Base Protocol AVPs
    pub const SESSION_ID: u32 = 263;
    pub const ORIGIN_HOST: u32 = 264;
    pub const ORIGIN_REALM: u32 = 296;
    pub const DESTINATION_HOST: u32 = 293;
    pub const DESTINATION_REALM: u32 = 283;
    pub const USER_NAME: u32 = 1;
    pub const RESULT_CODE: u32 = 268;
    pub const AUTH_SESSION_STATE: u32 = 277;
    pub const AUTH_APPLICATION_ID: u32 = 258;
    pub const VENDOR_ID: u32 = 266;
    pub const VENDOR_SPECIFIC_APPLICATION_ID: u32 = 260;
    pub const EXPERIMENTAL_RESULT: u32 = 297;
    pub const EXPERIMENTAL_RESULT_CODE: u32 = 298;
    pub const ORIGIN_STATE_ID: u32 = 278;
    pub const EVENT_TIMESTAMP: u32 = 55;
    pub const TERMINATION_CAUSE: u32 = 295;
    pub const AUTH_REQUEST_TYPE: u32 = 274;
    pub const RE_AUTH_REQUEST_TYPE: u32 = 285;
    pub const AUTHORIZATION_LIFETIME: u32 = 291;
    pub const AUTH_GRACE_PERIOD: u32 = 276;
    pub const SESSION_TIMEOUT: u32 = 27;
    pub const SERVICE_CONTEXT_ID: u32 = 461;

    // Subscription ID AVPs
    pub const SUBSCRIPTION_ID: u32 = 443;
    pub const SUBSCRIPTION_ID_TYPE: u32 = 450;
    pub const SUBSCRIPTION_ID_DATA: u32 = 444;

    // MIP AVPs
    pub const MIP6_AGENT_INFO: u32 = 486;
    pub const MIP_HOME_AGENT_ADDRESS: u32 = 334;

    // 3GPP specific AVPs
    pub const RAT_TYPE: u32 = 1032;
    pub const SERVICE_SELECTION: u32 = 493;
    pub const VISITED_PLMN_ID: u32 = 1407;
    pub const VISITED_NETWORK_IDENTIFIER: u32 = 600;

    // Frame IP AVPs
    pub const FRAMED_IP_ADDRESS: u32 = 8;
    pub const FRAMED_IPV6_PREFIX: u32 = 97;
}

/// Termination cause values
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

/// Subscription ID type values
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum SubscriptionIdType {
    EndUserE164 = 0,
    EndUserImsi = 1,
    EndUserSipUri = 2,
    EndUserNai = 3,
}

/// Auth session state values
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum AuthSessionState {
    StateMaintained = 0,
    NoStateMaintained = 1,
}

/// Auth request type values
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum AuthRequestType {
    AuthenticateOnly = 1,
    AuthorizeOnly = 2,
    AuthorizeAuthenticate = 3,
}

/// Re-Auth request type values
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ReAuthRequestType {
    AuthorizeOnly = 0,
    AuthorizeAuthenticate = 1,
}

/// RAT type values (3GPP TS 29.212)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum RatType {
    Wlan = 0,
    Virtual = 1,
    Utran = 1000,
    Geran = 1001,
    Gan = 1002,
    HspaEvolution = 1003,
    Eutran = 1004,
    EutranNbIot = 1005,
    Cdma20001X = 2000,
    Hrpd = 2001,
    Umb = 2002,
    Ehrpd = 2003,
}

/// Vendor-Specific-Application-Id structure
#[derive(Debug, Clone)]
pub struct VendorSpecificApplicationId {
    pub vendor_id: u32,
    pub auth_application_id: Option<u32>,
    pub acct_application_id: Option<u32>,
}

impl Default for VendorSpecificApplicationId {
    fn default() -> Self {
        Self {
            vendor_id: OGS_3GPP_VENDOR_ID,
            auth_application_id: None,
            acct_application_id: None,
        }
    }
}

/// Experimental-Result structure
#[derive(Debug, Clone)]
pub struct ExperimentalResult {
    pub vendor_id: u32,
    pub experimental_result_code: u32,
}

impl ExperimentalResult {
    pub fn new(result_code: u32) -> Self {
        Self {
            vendor_id: OGS_3GPP_VENDOR_ID,
            experimental_result_code: result_code,
        }
    }
}

/// Subscription-Id structure
#[derive(Debug, Clone)]
pub struct SubscriptionId {
    pub subscription_id_type: SubscriptionIdType,
    pub subscription_id_data: String,
}

impl SubscriptionId {
    pub fn new_imsi(imsi: &str) -> Self {
        Self {
            subscription_id_type: SubscriptionIdType::EndUserImsi,
            subscription_id_data: imsi.to_string(),
        }
    }

    pub fn new_e164(msisdn: &str) -> Self {
        Self {
            subscription_id_type: SubscriptionIdType::EndUserE164,
            subscription_id_data: msisdn.to_string(),
        }
    }
}

/// MIP6-Agent-Info structure
#[derive(Debug, Clone, Default)]
pub struct Mip6AgentInfo {
    pub mip_home_agent_address: Vec<std::net::IpAddr>,
}
