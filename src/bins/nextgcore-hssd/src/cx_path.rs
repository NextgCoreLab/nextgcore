//! HSS Cx Diameter Path
//!
//! Port of src/hss/hss-cx-path.c - Cx interface handlers for IMS authentication
//! Handles UAR (User-Authorization-Request), MAR (Multimedia-Auth-Request),
//! SAR (Server-Assignment-Request), LIR (Location-Info-Request)

use crate::fd_path::diam_stats;

/// Cx Application ID
pub const OGS_DIAM_CX_APPLICATION_ID: u32 = 16777216;

/// Server Assignment Types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerAssignmentType {
    NoAssignment = 0,
    Registration = 1,
    ReRegistration = 2,
    Unregistered = 3,
    TimeoutDeregistration = 4,
    UserDeregistration = 5,
    TimeoutDeregistrationStore = 6,
    UserDeregistrationStore = 7,
    AdminDeregistration = 8,
    AuthenticationFailure = 9,
    AuthenticationTimeout = 10,
    Deregistration = 11,
}

impl From<u32> for ServerAssignmentType {
    fn from(value: u32) -> Self {
        match value {
            0 => ServerAssignmentType::NoAssignment,
            1 => ServerAssignmentType::Registration,
            2 => ServerAssignmentType::ReRegistration,
            3 => ServerAssignmentType::Unregistered,
            4 => ServerAssignmentType::TimeoutDeregistration,
            5 => ServerAssignmentType::UserDeregistration,
            6 => ServerAssignmentType::TimeoutDeregistrationStore,
            7 => ServerAssignmentType::UserDeregistrationStore,
            8 => ServerAssignmentType::AdminDeregistration,
            9 => ServerAssignmentType::AuthenticationFailure,
            10 => ServerAssignmentType::AuthenticationTimeout,
            11 => ServerAssignmentType::Deregistration,
            _ => ServerAssignmentType::NoAssignment,
        }
    }
}

/// User Authorization Types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserAuthorizationType {
    Registration = 0,
    DeRegistration = 1,
    RegistrationAndCapabilities = 2,
}

impl From<u32> for UserAuthorizationType {
    fn from(value: u32) -> Self {
        match value {
            0 => UserAuthorizationType::Registration,
            1 => UserAuthorizationType::DeRegistration,
            2 => UserAuthorizationType::RegistrationAndCapabilities,
            _ => UserAuthorizationType::Registration,
        }
    }
}

/// Cx Result Codes
pub const OGS_DIAM_CX_FIRST_REGISTRATION: u32 = 2001;
pub const OGS_DIAM_CX_SUBSEQUENT_REGISTRATION: u32 = 2002;
pub const OGS_DIAM_CX_UNREGISTERED_SERVICE: u32 = 2003;
pub const OGS_DIAM_CX_ERROR_USER_UNKNOWN: u32 = 5001;
pub const OGS_DIAM_CX_ERROR_IDENTITIES_DONT_MATCH: u32 = 5002;
pub const OGS_DIAM_CX_ERROR_IDENTITY_NOT_REGISTERED: u32 = 5003;
pub const OGS_DIAM_CX_ERROR_ROAMING_NOT_ALLOWED: u32 = 5004;

/// Initialize Cx interface
pub fn hss_cx_init() -> Result<(), String> {
    log::info!("Initializing HSS Cx interface");
    // Note: Register Cx Diameter handlers
    // - UAR callback (User-Authorization-Request)
    // - MAR callback (Multimedia-Auth-Request)
    // - SAR callback (Server-Assignment-Request)
    // - LIR callback (Location-Info-Request)
    // Handler registration is done by the fd_path module when FreeDiameter is initialized
    Ok(())
}

/// Finalize Cx interface
pub fn hss_cx_final() {
    log::info!("Finalizing HSS Cx interface");
}

/// Handle User-Authorization-Request (UAR)
///
/// This is called by I-CSCF to authorize a user for registration
pub fn handle_uar(
    user_name: &str,
    public_identity: &str,
    _visited_network_identifier: &str,
    _authorization_type: UserAuthorizationType,
) -> Result<UarResponse, String> {
    log::debug!("[{}] Handling UAR for {}", user_name, public_identity);
    diam_stats().cx.inc_rx_uar();

    // Note: Implement UAR handling
    // 1. Check if user exists in DB
    // 2. Associate identity if needed
    // 3. Return UAA with server capabilities or assigned S-CSCF
    // UAR processing uses ogs_dbi for DB access and identity association

    diam_stats().cx.inc_tx_uaa();
    Ok(UarResponse::default())
}

/// Handle Multimedia-Auth-Request (MAR)
///
/// This is called by S-CSCF to get authentication vectors for IMS
pub fn handle_mar(
    user_name: &str,
    public_identity: &str,
    _sip_num_auth_items: u32,
    _sip_auth_scheme: &str,
    _sip_authorization: Option<&[u8]>,
) -> Result<MarResponse, String> {
    log::debug!("[{}] Handling MAR for {}", user_name, public_identity);
    diam_stats().cx.inc_rx_mar();

    // Note: Implement MAR handling
    // 1. Get auth info from DB
    // 2. Generate SIP authentication vectors (AKA or Digest)
    // 3. Return MAA with SIP-Auth-Data-Item
    // MAR processing uses ogs_dbi for DB access and ogs_crypt for auth vector generation

    diam_stats().cx.inc_tx_maa();
    Ok(MarResponse::default())
}

/// Handle Server-Assignment-Request (SAR)
///
/// This is called by S-CSCF to register/deregister a user
pub fn handle_sar(
    user_name: &str,
    public_identity: &str,
    _server_name: &str,
    server_assignment_type: ServerAssignmentType,
) -> Result<SarResponse, String> {
    log::debug!(
        "[{}] Handling SAR for {} (type={:?})",
        user_name,
        public_identity,
        server_assignment_type
    );
    diam_stats().cx.inc_rx_sar();

    // Note: Implement SAR handling
    // 1. Update server assignment in context
    // 2. Download user data if registration
    // 3. Return SAA with User-Data (XML)
    // SAR processing uses ogs_dbi for DB access and IMS user profile management

    diam_stats().cx.inc_tx_saa();
    Ok(SarResponse::default())
}

/// Handle Location-Info-Request (LIR)
///
/// This is called by I-CSCF to get the S-CSCF for a user
pub fn handle_lir(public_identity: &str) -> Result<LirResponse, String> {
    log::debug!("Handling LIR for {}", public_identity);
    diam_stats().cx.inc_rx_lir();

    // Note: Implement LIR handling
    // 1. Look up server name for public identity
    // 2. Return LIA with Server-Name or Server-Capabilities
    // LIR processing uses ogs_dbi for DB access and S-CSCF lookup

    diam_stats().cx.inc_tx_lia();
    Ok(LirResponse::default())
}

/// UAR Response structure
#[derive(Debug, Default)]
pub struct UarResponse {
    /// Result code
    pub result_code: u32,
    /// Experimental result code
    pub experimental_result_code: u32,
    /// Server name (assigned S-CSCF)
    pub server_name: Option<String>,
    /// Server capabilities
    pub server_capabilities: Option<ServerCapabilities>,
}

/// MAR Response structure
#[derive(Debug, Default)]
pub struct MarResponse {
    /// Result code
    pub result_code: u32,
    /// User name (IMPI)
    pub user_name: Option<String>,
    /// Public identity
    pub public_identity: Option<String>,
    /// Number of auth items
    pub sip_num_auth_items: u32,
    /// Authentication data items
    pub sip_auth_data_items: Vec<SipAuthDataItem>,
}

/// SAR Response structure
#[derive(Debug, Default)]
pub struct SarResponse {
    /// Result code
    pub result_code: u32,
    /// User data (XML)
    pub user_data: Option<String>,
    /// Charging information
    pub charging_information: Option<ChargingInformation>,
}

/// LIR Response structure
#[derive(Debug, Default)]
pub struct LirResponse {
    /// Result code
    pub result_code: u32,
    /// Experimental result code
    pub experimental_result_code: u32,
    /// Server name
    pub server_name: Option<String>,
    /// Server capabilities
    pub server_capabilities: Option<ServerCapabilities>,
}

/// Server Capabilities structure
#[derive(Debug, Default, Clone)]
pub struct ServerCapabilities {
    /// Mandatory capabilities
    pub mandatory_capability: Vec<u32>,
    /// Optional capabilities
    pub optional_capability: Vec<u32>,
    /// Server name
    pub server_name: Vec<String>,
}

/// SIP Authentication Data Item
#[derive(Debug, Default, Clone)]
pub struct SipAuthDataItem {
    /// Authentication scheme
    pub sip_auth_scheme: String,
    /// Authentication data (RAND, AUTN, etc.)
    pub sip_authenticate: Vec<u8>,
    /// Authorization data
    pub sip_authorization: Vec<u8>,
    /// Confidentiality key
    pub confidentiality_key: Vec<u8>,
    /// Integrity key
    pub integrity_key: Vec<u8>,
}

/// Charging Information structure
#[derive(Debug, Default, Clone)]
pub struct ChargingInformation {
    /// Primary event charging function name
    pub primary_event_charging_function_name: Option<String>,
    /// Secondary event charging function name
    pub secondary_event_charging_function_name: Option<String>,
    /// Primary charging collection function name
    pub primary_charging_collection_function_name: Option<String>,
    /// Secondary charging collection function name
    pub secondary_charging_collection_function_name: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_server_assignment_type_from_u32() {
        assert_eq!(ServerAssignmentType::from(1), ServerAssignmentType::Registration);
        assert_eq!(ServerAssignmentType::from(5), ServerAssignmentType::UserDeregistration);
        assert_eq!(ServerAssignmentType::from(99), ServerAssignmentType::NoAssignment);
    }

    #[test]
    fn test_user_authorization_type_from_u32() {
        assert_eq!(UserAuthorizationType::from(0), UserAuthorizationType::Registration);
        assert_eq!(UserAuthorizationType::from(1), UserAuthorizationType::DeRegistration);
    }

    #[test]
    fn test_cx_init_final() {
        assert!(hss_cx_init().is_ok());
        hss_cx_final();
    }

    #[test]
    fn test_handle_uar() {
        let result = handle_uar(
            "user@example.com",
            "sip:user@example.com",
            "example.com",
            UserAuthorizationType::Registration,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_handle_mar() {
        let result = handle_mar(
            "user@example.com",
            "sip:user@example.com",
            1,
            "Digest-AKAv1-MD5",
            None,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_handle_sar() {
        let result = handle_sar(
            "user@example.com",
            "sip:user@example.com",
            "sip:scscf.example.com",
            ServerAssignmentType::Registration,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_handle_lir() {
        let result = handle_lir("sip:user@example.com");
        assert!(result.is_ok());
    }
}
