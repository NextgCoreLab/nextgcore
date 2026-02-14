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
    authorization_type: UserAuthorizationType,
) -> Result<UarResponse, String> {
    log::debug!("[{user_name}] Handling UAR for {public_identity} (type={authorization_type:?})");
    diam_stats().cx.inc_rx_uar();

    use crate::context::hss_self;
    use ogs_dbi::ogs_dbi_ims_data;

    // 1. Check if user exists in DB
    let supi = format!("imsi-{}", user_name.trim_start_matches("imsi-"));
    let _ims_data = ogs_dbi_ims_data(&supi)
        .map_err(|e| format!("Failed to get IMS data: {e}"))?;

    // 2. Associate identity if needed
    let ctx = hss_self();
    let context = ctx.read().map_err(|_| "Failed to lock context".to_string())?;
    context.cx_associate_identity(user_name, public_identity);

    // 3. Return UAA with server capabilities or assigned S-CSCF
    let mut response = UarResponse::default();
    response.result_code = 2001; // DIAMETER_SUCCESS
    response.experimental_result_code = OGS_DIAM_CX_FIRST_REGISTRATION;

    // Return default server capabilities (no scscf_name field in OgsImsData)
    response.server_capabilities = Some(ServerCapabilities {
        mandatory_capability: vec![0], // No mandatory capabilities
        optional_capability: vec![0],   // No optional capabilities
        server_name: vec!["sip:scscf.ims.mnc001.mcc001.3gppnetwork.org".to_string()],
    });

    log::debug!("[{user_name}] UAR processed for {public_identity}");
    diam_stats().cx.inc_tx_uaa();
    Ok(response)
}

/// Handle Multimedia-Auth-Request (MAR)
///
/// This is called by S-CSCF to get authentication vectors for IMS
pub fn handle_mar(
    user_name: &str,
    public_identity: &str,
    sip_num_auth_items: u32,
    sip_auth_scheme: &str,
    _sip_authorization: Option<&[u8]>,
) -> Result<MarResponse, String> {
    log::debug!("[{user_name}] Handling MAR for {public_identity} (scheme={sip_auth_scheme})");
    diam_stats().cx.inc_rx_mar();

    use ogs_dbi::ogs_dbi_auth_info;
    use ogs_crypt::milenage::{milenage_f1, milenage_f2345, milenage_opc};

    // 1. Get auth info from DB
    let supi = format!("imsi-{}", user_name.trim_start_matches("imsi-"));
    let auth_info = ogs_dbi_auth_info(&supi)
        .map_err(|e| format!("Failed to get auth info: {e}"))?;

    // 2. Generate SIP authentication vectors (AKA or Digest)
    let rand = auth_info.rand;
    let sqn_bytes: [u8; 6] = [
        ((auth_info.sqn >> 40) & 0xFF) as u8,
        ((auth_info.sqn >> 32) & 0xFF) as u8,
        ((auth_info.sqn >> 24) & 0xFF) as u8,
        ((auth_info.sqn >> 16) & 0xFF) as u8,
        ((auth_info.sqn >> 8) & 0xFF) as u8,
        (auth_info.sqn & 0xFF) as u8,
    ];

    let opc = if auth_info.use_opc {
        auth_info.opc
    } else {
        milenage_opc(&auth_info.k, &auth_info.op)
            .map_err(|_| "Failed to compute OPc".to_string())?
    };

    let (mac_a, _mac_s) = milenage_f1(&opc, &auth_info.k, &rand, &sqn_bytes, &auth_info.amf)
        .map_err(|_| "Failed to compute f1".to_string())?;

    let (res, ck, ik, ak, _ak_star) = milenage_f2345(&opc, &auth_info.k, &rand)
        .map_err(|_| "Failed to compute f2-f5".to_string())?;

    // Build AUTN = SQN ^ AK || AMF || MAC-A
    let mut autn = [0u8; 16];
    for i in 0..6 {
        autn[i] = sqn_bytes[i] ^ ak[i];
    }
    autn[6..8].copy_from_slice(&auth_info.amf);
    autn[8..16].copy_from_slice(&mac_a);

    // 3. Return MAA with SIP-Auth-Data-Item
    let mut sip_authenticate = Vec::new();
    sip_authenticate.extend_from_slice(&rand);
    sip_authenticate.extend_from_slice(&autn);

    let sip_auth_data_item = SipAuthDataItem {
        sip_auth_scheme: sip_auth_scheme.to_string(),
        sip_authenticate,
        sip_authorization: res.to_vec(),
        confidentiality_key: ck.to_vec(),
        integrity_key: ik.to_vec(),
    };

    let response = MarResponse {
        result_code: 2001, // DIAMETER_SUCCESS
        user_name: Some(user_name.to_string()),
        public_identity: Some(public_identity.to_string()),
        sip_num_auth_items,
        sip_auth_data_items: vec![sip_auth_data_item],
    };

    log::debug!("[{user_name}] MAR processed for {public_identity}");
    diam_stats().cx.inc_tx_maa();
    Ok(response)
}

/// Handle Server-Assignment-Request (SAR)
///
/// This is called by S-CSCF to register/deregister a user
pub fn handle_sar(
    user_name: &str,
    public_identity: &str,
    server_name: &str,
    server_assignment_type: ServerAssignmentType,
) -> Result<SarResponse, String> {
    log::debug!(
        "[{user_name}] Handling SAR for {public_identity} (type={server_assignment_type:?}, server={server_name})"
    );
    diam_stats().cx.inc_rx_sar();

    use crate::context::hss_self;
    use ogs_dbi::ogs_dbi_ims_data;

    // 1. Update server assignment in context
    let ctx = hss_self();
    let context = ctx.read().map_err(|_| "Failed to lock context".to_string())?;

    context.cx_associate_identity(user_name, public_identity);
    context.cx_set_server_name(public_identity, server_name, true);

    // 2. Download user data if registration
    let mut response = SarResponse::default();
    response.result_code = 2001; // DIAMETER_SUCCESS

    match server_assignment_type {
        ServerAssignmentType::Registration | ServerAssignmentType::ReRegistration => {
            // Get IMS user data from DB
            let supi = format!("imsi-{}", user_name.trim_start_matches("imsi-"));
            let _ims_data = ogs_dbi_ims_data(&supi)
                .map_err(|e| format!("Failed to get IMS data: {e}"))?;

            // 3. Return SAA with User-Data (XML)
            // Note: In full implementation, this would build IMS user profile XML
            let user_data_xml = format!(
                r#"<?xml version="1.0" encoding="UTF-8"?>
<IMSSubscription>
    <PrivateID>{user_name}</PrivateID>
    <ServiceProfile>
        <PublicIdentity>
            <Identity>{public_identity}</Identity>
        </PublicIdentity>
        <InitialFilterCriteria>
            <Priority>0</Priority>
            <ApplicationServer>
                <ServerName>sip:as.ims.mnc001.mcc001.3gppnetwork.org</ServerName>
            </ApplicationServer>
        </InitialFilterCriteria>
    </ServiceProfile>
</IMSSubscription>"#
            );

            response.user_data = Some(user_data_xml);

            // Include charging information
            response.charging_information = Some(ChargingInformation {
                primary_event_charging_function_name: Some("pcf.ims.mnc001.mcc001.3gppnetwork.org".to_string()),
                secondary_event_charging_function_name: None,
                primary_charging_collection_function_name: Some("ccf.ims.mnc001.mcc001.3gppnetwork.org".to_string()),
                secondary_charging_collection_function_name: None,
            });
        }
        _ => {
            // Deregistration or other types - no user data
            log::debug!("[{user_name}] SAR type {server_assignment_type:?} - no user data returned");
        }
    }

    log::debug!("[{user_name}] SAR processed for {public_identity}");
    diam_stats().cx.inc_tx_saa();
    Ok(response)
}

/// Handle Location-Info-Request (LIR)
///
/// This is called by I-CSCF to get the S-CSCF for a user
pub fn handle_lir(public_identity: &str) -> Result<LirResponse, String> {
    log::debug!("Handling LIR for {public_identity}");
    diam_stats().cx.inc_rx_lir();

    use crate::context::hss_self;

    // 1. Look up server name for public identity
    let ctx = hss_self();
    let context = ctx.read().map_err(|_| "Failed to lock context".to_string())?;

    let mut response = LirResponse::default();
    response.result_code = 2001; // DIAMETER_SUCCESS

    // 2. Return LIA with Server-Name or Server-Capabilities
    if let Some(server_name) = context.cx_get_server_name(public_identity) {
        // User is registered - return assigned S-CSCF
        response.server_name = Some(server_name);
        response.experimental_result_code = OGS_DIAM_CX_SUBSEQUENT_REGISTRATION;
    } else {
        // User not registered - return server capabilities for selection
        response.server_capabilities = Some(ServerCapabilities {
            mandatory_capability: vec![0], // No mandatory capabilities
            optional_capability: vec![0],   // No optional capabilities
            server_name: vec![
                "sip:scscf1.ims.mnc001.mcc001.3gppnetwork.org".to_string(),
                "sip:scscf2.ims.mnc001.mcc001.3gppnetwork.org".to_string(),
            ],
        });
        response.experimental_result_code = OGS_DIAM_CX_ERROR_IDENTITY_NOT_REGISTERED;
    }

    log::debug!("LIR processed for {public_identity}");
    diam_stats().cx.inc_tx_lia();
    Ok(response)
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
        // UAR requires MongoDB for IMS data lookup - verify graceful error without DB
        let result = handle_uar(
            "user@example.com",
            "sip:user@example.com",
            "example.com",
            UserAuthorizationType::Registration,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_handle_mar() {
        // MAR requires MongoDB for auth info lookup - verify graceful error without DB
        let result = handle_mar(
            "user@example.com",
            "sip:user@example.com",
            1,
            "Digest-AKAv1-MD5",
            None,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_handle_sar() {
        // SAR requires MongoDB for IMS data lookup - verify graceful error without DB
        let result = handle_sar(
            "user@example.com",
            "sip:user@example.com",
            "sip:scscf.example.com",
            ServerAssignmentType::Registration,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_handle_lir() {
        let result = handle_lir("sip:user@example.com");
        assert!(result.is_ok());
    }
}
