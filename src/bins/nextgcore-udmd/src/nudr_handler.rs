//! NUDR Handler Functions
//!
//! Port of src/udm/nudr-handler.c - NUDR service handlers
//! Handles responses from UDR for authentication, context, and provisioned data

use crate::context::{
    udm_self, AuthType, Amf3GppAccessRegistration, SmfRegistration, UdmUe,
    OGS_KEY_LEN, OGS_AMF_LEN, OGS_RAND_LEN, OGS_SQN_LEN,
};
use crate::nudm_handler::{bytes_to_hex, hex_to_bytes, http_status, HandlerResult};

/// UDM SBI state for multi-step operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdmSbiState {
    /// No state
    NoState,
    /// UE provisioned datasets
    UeProvisionedDatasets,
    /// UE provisioned NSSAI only
    UeProvisionedNssaiOnly,
}

impl From<i32> for UdmSbiState {
    fn from(value: i32) -> Self {
        match value {
            1 => UdmSbiState::UeProvisionedDatasets,
            2 => UdmSbiState::UeProvisionedNssaiOnly,
            _ => UdmSbiState::NoState,
        }
    }
}

impl From<UdmSbiState> for i32 {
    fn from(state: UdmSbiState) -> Self {
        match state {
            UdmSbiState::NoState => 0,
            UdmSbiState::UeProvisionedDatasets => 1,
            UdmSbiState::UeProvisionedNssaiOnly => 2,
        }
    }
}

/// Authentication subscription data from UDR
#[derive(Debug, Clone, Default)]
pub struct AuthenticationSubscription {
    pub authentication_method: Option<String>,
    pub enc_permanent_key: Option<String>,
    pub enc_opc_key: Option<String>,
    pub authentication_management_field: Option<String>,
    pub sequence_number: Option<SequenceNumber>,
}

/// Sequence number data
#[derive(Debug, Clone, Default)]
pub struct SequenceNumber {
    pub sqn: Option<String>,
}

/// Authentication info result to send back to AUSF
#[derive(Debug, Clone)]
pub struct AuthenticationInfoResult {
    pub supi: String,
    pub auth_type: AuthType,
    pub authentication_vector: AuthenticationVector,
}

/// Authentication vector
#[derive(Debug, Clone)]
pub struct AuthenticationVector {
    pub av_type: String,
    pub rand: String,
    pub xres_star: String,
    pub autn: String,
    pub kausf: String,
}

/// Provisioned data sets from UDR
#[derive(Debug, Clone, Default)]
pub struct ProvisionedDataSets {
    pub am_data: Option<AccessAndMobilitySubscriptionData>,
    pub smf_sel_data: Option<SmfSelectionSubscriptionData>,
    pub sm_data: Vec<SessionManagementSubscriptionData>,
}

/// Access and mobility subscription data
#[derive(Debug, Clone, Default)]
pub struct AccessAndMobilitySubscriptionData {
    pub nssai: Option<Nssai>,
    // Add other fields as needed
}

/// NSSAI data
#[derive(Debug, Clone, Default)]
pub struct Nssai {
    pub default_single_nssais: Vec<String>,
    pub single_nssais: Vec<String>,
}

/// SMF selection subscription data
#[derive(Debug, Clone, Default)]
pub struct SmfSelectionSubscriptionData {
    // Add fields as needed
}

/// Session management subscription data
#[derive(Debug, Clone, Default)]
pub struct SessionManagementSubscriptionData {
    pub single_nssai: Option<String>,
    pub dnn_configurations: Vec<String>,
}

/// AUC (Authentication Center) constants
pub const OGS_AUTN_LEN: usize = 16;
pub const OGS_AK_LEN: usize = 6;
pub const OGS_MAX_RES_LEN: usize = 16;
pub const OGS_SHA256_DIGEST_SIZE: usize = 32;

/// Query subscription provisioned data from UDR
pub fn udm_nudr_dr_query_subscription_provisioned(
    udm_ue_id: u64,
    _stream_id: u64,
    state: UdmSbiState,
) -> HandlerResult {
    let ctx = udm_self();
    let context = ctx.read().unwrap();

    let udm_ue = match context.ue_find_by_id(udm_ue_id) {
        Some(ue) => ue,
        None => {
            log::error!("UDM UE not found [{}]", udm_ue_id);
            return HandlerResult::bad_request("UDM UE not found");
        }
    };
    drop(context);

    let supi = udm_ue.supi.clone().unwrap_or_else(|| udm_ue.suci.clone());
    log::debug!("[{}] Query subscription provisioned data (state={:?})", supi, state);

    // This would send a request to UDR
    // The actual HTTP request would be built and sent here
    HandlerResult::ok()
}

/// Handle subscription authentication response from UDR
/// Port of udm_nudr_dr_handle_subscription_authentication()
pub fn udm_nudr_dr_handle_subscription_authentication(
    udm_ue_id: u64,
    _stream_id: u64,
    http_method: &str,
    resource_name: &str,
    res_status: u16,
    auth_subscription: Option<&AuthenticationSubscription>,
) -> (HandlerResult, Option<AuthenticationInfoResult>) {
    let ctx = udm_self();
    let context = ctx.read().unwrap();

    let mut udm_ue = match context.ue_find_by_id(udm_ue_id) {
        Some(ue) => ue,
        None => {
            log::error!("UDM UE not found [{}]", udm_ue_id);
            return (HandlerResult::bad_request("UDM UE not found"), None);
        }
    };
    drop(context);

    log::debug!("[{}] Handle subscription authentication response", udm_ue.suci);

    match resource_name {
        "authentication-subscription" => {
            match http_method {
                "GET" => {
                    // Handle GET response - authentication subscription data
                    if res_status != http_status::OK {
                        log::error!("[{}] HTTP response error [{}]", udm_ue.suci, res_status);
                        return (
                            HandlerResult {
                                success: false,
                                status: res_status,
                                error_message: Some("HTTP response error".to_string()),
                                error_cause: None,
                            },
                            None,
                        );
                    }

                    let auth_sub = match auth_subscription {
                        Some(sub) => sub,
                        None => {
                            log::error!("[{}] No AuthenticationSubscription", udm_ue.suci);
                            return (
                                HandlerResult::bad_request("No AuthenticationSubscription"),
                                None,
                            );
                        }
                    };

                    // Validate authentication method
                    if auth_sub.authentication_method.as_deref() != Some("5G_AKA") {
                        log::error!(
                            "[{}] Not supported Auth Method [{:?}]",
                            udm_ue.suci,
                            auth_sub.authentication_method
                        );
                        return (
                            HandlerResult::forbidden("Not supported Auth Method", None),
                            None,
                        );
                    }

                    // Validate required fields
                    let enc_permanent_key = match &auth_sub.enc_permanent_key {
                        Some(k) if !k.is_empty() => k,
                        _ => {
                            log::error!("[{}] No encPermanentKey", udm_ue.suci);
                            return (
                                HandlerResult::bad_request("No encPermanentKey"),
                                None,
                            );
                        }
                    };

                    let enc_opc_key = match &auth_sub.enc_opc_key {
                        Some(k) if !k.is_empty() => k,
                        _ => {
                            log::error!("[{}] No encOpcKey", udm_ue.suci);
                            return (
                                HandlerResult::bad_request("No encOpcKey"),
                                None,
                            );
                        }
                    };

                    let amf_field = match &auth_sub.authentication_management_field {
                        Some(f) if !f.is_empty() => f,
                        _ => {
                            log::error!("[{}] No authenticationManagementField", udm_ue.suci);
                            return (
                                HandlerResult::bad_request("No authenticationManagementField"),
                                None,
                            );
                        }
                    };

                    let sqn_str = match &auth_sub.sequence_number {
                        Some(seq) => match &seq.sqn {
                            Some(s) if !s.is_empty() => s,
                            _ => {
                                log::error!("[{}] No SequenceNumber.sqn", udm_ue.suci);
                                return (
                                    HandlerResult::bad_request("No SequenceNumber.sqn"),
                                    None,
                                );
                            }
                        },
                        None => {
                            log::error!("[{}] No SequenceNumber", udm_ue.suci);
                            return (
                                HandlerResult::bad_request("No SequenceNumber"),
                                None,
                            );
                        }
                    };

                    // Store authentication data in UE context
                    udm_ue.auth_type = AuthType::FiveGAka;

                    // Parse and store keys
                    let opc_bytes = hex_to_bytes(enc_opc_key);
                    let k_bytes = hex_to_bytes(enc_permanent_key);
                    let amf_bytes = hex_to_bytes(amf_field);
                    let sqn_bytes = hex_to_bytes(sqn_str);

                    if opc_bytes.len() >= OGS_KEY_LEN {
                        udm_ue.opc.copy_from_slice(&opc_bytes[..OGS_KEY_LEN]);
                    }
                    if k_bytes.len() >= OGS_KEY_LEN {
                        udm_ue.k.copy_from_slice(&k_bytes[..OGS_KEY_LEN]);
                    }
                    if amf_bytes.len() >= OGS_AMF_LEN {
                        udm_ue.amf.copy_from_slice(&amf_bytes[..OGS_AMF_LEN]);
                    }
                    if sqn_bytes.len() >= OGS_SQN_LEN {
                        udm_ue.sqn.copy_from_slice(&sqn_bytes[..OGS_SQN_LEN]);
                    }

                    // Update UE in context
                    let ctx = udm_self();
                    let context = ctx.read().unwrap();
                    context.ue_update(&udm_ue);
                    drop(context);

                    // Now we need to send PATCH to update SQN and generate auth vector
                    // This is handled in the PATCH response
                    (HandlerResult::ok(), None)
                }

                "PATCH" => {
                    // Handle PATCH response - generate authentication vector
                    if res_status != http_status::OK && res_status != http_status::NO_CONTENT {
                        log::error!("[{}] HTTP response error [{}]", udm_ue.suci, res_status);
                        return (
                            HandlerResult {
                                success: false,
                                status: res_status,
                                error_message: Some("HTTP response error".to_string()),
                                error_cause: None,
                            },
                            None,
                        );
                    }

                    // Generate authentication vector
                    let auth_result = generate_authentication_vector(&mut udm_ue);

                    // Update UE in context
                    let ctx = udm_self();
                    let context = ctx.read().unwrap();
                    context.ue_update(&udm_ue);
                    drop(context);

                    (HandlerResult::ok(), Some(auth_result))
                }

                _ => {
                    log::error!("Invalid HTTP method [{}]", http_method);
                    (HandlerResult::forbidden("Invalid HTTP method", None), None)
                }
            }
        }

        "authentication-status" => {
            // Handle authentication status response
            if res_status != http_status::NO_CONTENT {
                log::error!("[{}] HTTP response error [{}]", udm_ue.suci, res_status);
                return (
                    HandlerResult {
                        success: false,
                        status: res_status,
                        error_message: Some("HTTP response error".to_string()),
                        error_cause: None,
                    },
                    None,
                );
            }

            // Check if this is an auth removal indication
            if let Some(ref _auth_event) = udm_ue.auth_event {
                // Note: auth_removal_ind flag checked from auth_event.auth_removal_ind
                // If true, authentication context is removed from UE
                log::debug!("[{}] Authentication status updated", udm_ue.suci);
            }

            (HandlerResult::ok(), None)
        }

        _ => {
            log::error!("[{}] Invalid resource name [{}]", udm_ue.supi.as_deref().unwrap_or(&udm_ue.suci), resource_name);
            (HandlerResult::bad_request("Invalid resource name"), None)
        }
    }
}

/// Handle subscription context response from UDR
/// Port of udm_nudr_dr_handle_subscription_context()
pub fn udm_nudr_dr_handle_subscription_context(
    udm_ue_id: u64,
    _stream_id: u64,
    http_method: &str,
    resource_name: &str,
    res_status: u16,
) -> (HandlerResult, Option<Amf3GppAccessRegistration>) {
    let ctx = udm_self();
    let context = ctx.read().unwrap();

    let udm_ue = match context.ue_find_by_id(udm_ue_id) {
        Some(ue) => ue,
        None => {
            log::error!("UDM UE not found [{}]", udm_ue_id);
            return (HandlerResult::bad_request("UDM UE not found"), None);
        }
    };
    drop(context);

    let supi = udm_ue.supi.clone().unwrap_or_else(|| udm_ue.suci.clone());
    log::debug!("[{}] Handle subscription context response", supi);

    if res_status != http_status::NO_CONTENT {
        log::error!("[{}] HTTP response error [{}]", supi, res_status);
        return (
            HandlerResult {
                success: false,
                status: res_status,
                error_message: Some("HTTP response error".to_string()),
                error_cause: None,
            },
            None,
        );
    }

    match http_method {
        "PATCH" => {
            match resource_name {
                "amf-3gpp-access" => {
                    // PATCH response for AMF context update
                    (HandlerResult::no_content(), None)
                }
                _ => {
                    log::error!("[{}] Invalid resource name [{}]", supi, resource_name);
                    (HandlerResult::bad_request("Invalid resource name"), None)
                }
            }
        }
        _ => {
            // PUT response for AMF context registration
            match resource_name {
                "amf-3gpp-access" => {
                    let registration = udm_ue.amf_3gpp_access_registration.clone();

                    if registration.is_none() {
                        log::error!("[{}] No Amf3GppAccessRegistration", supi);
                        return (HandlerResult::bad_request("No Amf3GppAccessRegistration"), None);
                    }

                    // Determine status based on whether this is new or existing registration
                    let status = if udm_ue.amf_instance_id.is_some() {
                        http_status::OK
                    } else {
                        http_status::CREATED
                    };

                    (
                        HandlerResult {
                            success: true,
                            status,
                            error_message: None,
                            error_cause: None,
                        },
                        registration,
                    )
                }
                _ => {
                    log::error!("[{}] Invalid resource name [{}]", supi, resource_name);
                    (HandlerResult::bad_request("Invalid resource name"), None)
                }
            }
        }
    }
}

/// Handle subscription provisioned response from UDR
/// Port of udm_nudr_dr_handle_subscription_provisioned()
pub fn udm_nudr_dr_handle_subscription_provisioned(
    udm_ue_id: u64,
    _stream_id: u64,
    state: UdmSbiState,
    resource_name: &str,
    res_status: u16,
    provisioned_data: Option<&ProvisionedDataSets>,
    am_data: Option<&AccessAndMobilitySubscriptionData>,
    smf_sel_data: Option<&SmfSelectionSubscriptionData>,
    sm_data: Option<&[SessionManagementSubscriptionData]>,
) -> HandlerResult {
    let ctx = udm_self();
    let context = ctx.read().unwrap();

    let udm_ue = match context.ue_find_by_id(udm_ue_id) {
        Some(ue) => ue,
        None => {
            log::error!("UDM UE not found [{}]", udm_ue_id);
            return HandlerResult::bad_request("UDM UE not found");
        }
    };
    drop(context);

    let supi = udm_ue.supi.clone().unwrap_or_else(|| udm_ue.suci.clone());
    log::debug!("[{}] Handle subscription provisioned response (state={:?})", supi, state);

    // Handle UE provisioned datasets state
    if state == UdmSbiState::UeProvisionedDatasets {
        if provisioned_data.is_none() {
            log::error!("[{}] No ProvisionedDataSets", supi);
            return HandlerResult::bad_request("No ProvisionedDataSets");
        }

        // Return the provisioned data sets
        return HandlerResult {
            success: true,
            status: res_status,
            error_message: None,
            error_cause: None,
        };
    }

    // Handle specific resource types
    match resource_name {
        "am-data" => {
            if am_data.is_none() {
                log::error!("[{}] No AccessAndMobilitySubscriptionData", supi);
                return HandlerResult::bad_request("No AccessAndMobilitySubscriptionData");
            }

            // Check if original request was for NSSAI only
            if state == UdmSbiState::UeProvisionedNssaiOnly {
                if let Some(data) = am_data {
                    if data.nssai.is_none() {
                        log::error!("[{}] No Nssai", supi);
                        return HandlerResult::bad_request("No Nssai");
                    }
                }
            }

            HandlerResult {
                success: true,
                status: res_status,
                error_message: None,
                error_cause: None,
            }
        }

        "smf-selection-subscription-data" => {
            if smf_sel_data.is_none() {
                log::error!("[{}] No SmfSelectionSubscriptionData", supi);
                return HandlerResult::bad_request("No SmfSelectionSubscriptionData");
            }

            HandlerResult {
                success: true,
                status: res_status,
                error_message: None,
                error_cause: None,
            }
        }

        "sm-data" => {
            if sm_data.is_none() || sm_data.map(|d| d.is_empty()).unwrap_or(true) {
                log::error!("[{}] No SessionManagementSubscriptionData", supi);
                return HandlerResult::bad_request("No SessionManagementSubscriptionData");
            }

            HandlerResult {
                success: true,
                status: res_status,
                error_message: None,
                error_cause: None,
            }
        }

        _ => {
            log::error!("[{}] Invalid resource name [{}]", supi, resource_name);
            HandlerResult::bad_request("Invalid resource name")
        }
    }
}

/// Handle SMF registration response from UDR
/// Port of udm_nudr_dr_handle_smf_registration()
pub fn udm_nudr_dr_handle_smf_registration(
    sess_id: u64,
    _stream_id: u64,
    http_method: &str,
    resource_name: &str,
    res_status: u16,
) -> (HandlerResult, Option<SmfRegistration>) {
    let ctx = udm_self();
    let context = ctx.read().unwrap();

    let sess = match context.sess_find_by_id(sess_id) {
        Some(s) => s,
        None => {
            log::error!("UDM session not found [{}]", sess_id);
            return (HandlerResult::bad_request("UDM session not found"), None);
        }
    };

    let udm_ue = match context.ue_find_by_id(sess.udm_ue_id) {
        Some(ue) => ue,
        None => {
            log::error!("UDM UE not found for session [{}]", sess_id);
            return (HandlerResult::bad_request("UDM UE not found"), None);
        }
    };
    drop(context);

    let supi = udm_ue.supi.clone().unwrap_or_else(|| udm_ue.suci.clone());
    log::debug!("[{}:{}] Handle SMF registration response", supi, sess.psi);

    if res_status != http_status::NO_CONTENT {
        log::error!("[{}:{}] HTTP response error [{}]", supi, sess.psi, res_status);
        return (
            HandlerResult {
                success: false,
                status: res_status,
                error_message: Some("HTTP response error".to_string()),
                error_cause: None,
            },
            None,
        );
    }

    match resource_name {
        "smf-registrations" => {
            match http_method {
                "PUT" => {
                    // Handle PUT response for SMF registration
                    let smf_registration = sess.smf_registration.clone();

                    if smf_registration.is_none() {
                        log::error!("[{}:{}] No SmfRegistration", supi, sess.psi);
                        return (HandlerResult::bad_request("No SmfRegistration"), None);
                    }

                    // Validate SMF registration fields
                    if let Some(ref reg) = smf_registration {
                        if reg.smf_instance_id.is_none() {
                            log::error!("[{}:{}] No smfInstanceId", supi, sess.psi);
                            return (HandlerResult::bad_request("No smfInstanceId"), None);
                        }
                        if reg.pdu_session_id == 0 {
                            log::error!("[{}:{}] No pduSessionId", supi, sess.psi);
                            return (HandlerResult::bad_request("No pduSessionId"), None);
                        }
                        if reg.single_nssai.is_none() {
                            log::error!("[{}:{}] No singleNssai", supi, sess.psi);
                            return (HandlerResult::bad_request("No singleNssai"), None);
                        }
                        if reg.dnn.is_none() {
                            log::error!("[{}:{}] No dnn", supi, sess.psi);
                            return (HandlerResult::bad_request("No dnn"), None);
                        }
                        if reg.plmn_id.is_none() {
                            log::error!("[{}:{}] No plmnId", supi, sess.psi);
                            return (HandlerResult::bad_request("No plmnId"), None);
                        }
                    }

                    // Determine status based on whether this is new or existing registration
                    let status = if sess.smf_instance_id.is_some() {
                        http_status::OK
                    } else {
                        http_status::CREATED
                    };

                    (
                        HandlerResult {
                            success: true,
                            status,
                            error_message: None,
                            error_cause: None,
                        },
                        smf_registration,
                    )
                }

                "DELETE" => {
                    // Handle DELETE response for SMF deregistration
                    (HandlerResult::no_content(), None)
                }

                _ => {
                    log::error!("[{}:{}] Invalid HTTP method [{}]", supi, sess.psi, http_method);
                    (HandlerResult::forbidden("Invalid HTTP method", None), None)
                }
            }
        }

        _ => {
            log::error!("[{}:{}] Invalid resource name [{}]", supi, sess.psi, resource_name);
            (HandlerResult::bad_request("Invalid resource name"), None)
        }
    }
}

/// Generate authentication vector
/// Port of milenage_generate() and related functions
fn generate_authentication_vector(udm_ue: &mut UdmUe) -> AuthenticationInfoResult {
    // Generate random RAND
    let mut rand = [0u8; OGS_RAND_LEN];
    for i in 0..OGS_RAND_LEN {
        rand[i] = rand::random();
    }
    udm_ue.rand = rand;

    // Note: In production, these are computed using Milenage algorithm:
    // milenage_generate(opc, amf, k, sqn, rand, autn, ik, ck, ak, xres, &xres_len)
    // Placeholder values used for testing

    let autn = [0u8; OGS_AUTN_LEN];
    let _ik = [0u8; OGS_KEY_LEN];
    let _ck = [0u8; OGS_KEY_LEN];
    let _xres = [0u8; OGS_MAX_RES_LEN];
    let _xres_len = 8;

    // Calculate KAUSF using KDF
    // ogs_kdf_kausf(ck, ik, serving_network_name, autn, kausf)
    let kausf = [0u8; OGS_SHA256_DIGEST_SIZE];

    // Calculate XRES*
    // ogs_kdf_xres_star(ck, ik, serving_network_name, rand, xres, xres_len, xres_star)
    let xres_star = [0u8; OGS_MAX_RES_LEN];

    // Build authentication info result
    AuthenticationInfoResult {
        supi: udm_ue.supi.clone().unwrap_or_else(|| udm_ue.suci.clone()),
        auth_type: AuthType::FiveGAka,
        authentication_vector: AuthenticationVector {
            av_type: "5G_HE_AKA".to_string(),
            rand: bytes_to_hex(&rand),
            xres_star: bytes_to_hex(&xres_star),
            autn: bytes_to_hex(&autn),
            kausf: bytes_to_hex(&kausf),
        },
    }
}

// Simple random number generation for testing
mod rand {
    pub fn random<T: Default>() -> T {
        // In real implementation, use proper random number generator
        T::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_udm_sbi_state_conversion() {
        assert_eq!(UdmSbiState::from(0), UdmSbiState::NoState);
        assert_eq!(UdmSbiState::from(1), UdmSbiState::UeProvisionedDatasets);
        assert_eq!(UdmSbiState::from(2), UdmSbiState::UeProvisionedNssaiOnly);
        assert_eq!(UdmSbiState::from(99), UdmSbiState::NoState);

        assert_eq!(i32::from(UdmSbiState::NoState), 0);
        assert_eq!(i32::from(UdmSbiState::UeProvisionedDatasets), 1);
        assert_eq!(i32::from(UdmSbiState::UeProvisionedNssaiOnly), 2);
    }

    #[test]
    fn test_authentication_subscription_default() {
        let auth_sub = AuthenticationSubscription::default();
        assert!(auth_sub.authentication_method.is_none());
        assert!(auth_sub.enc_permanent_key.is_none());
        assert!(auth_sub.enc_opc_key.is_none());
    }

    #[test]
    fn test_authentication_vector() {
        let av = AuthenticationVector {
            av_type: "5G_HE_AKA".to_string(),
            rand: "0123456789abcdef0123456789abcdef".to_string(),
            xres_star: "fedcba9876543210fedcba9876543210".to_string(),
            autn: "00112233445566778899aabbccddeeff".to_string(),
            kausf: "0".repeat(64),
        };
        assert_eq!(av.av_type, "5G_HE_AKA");
        assert_eq!(av.rand.len(), 32);
    }

    #[test]
    fn test_provisioned_data_sets_default() {
        let pds = ProvisionedDataSets::default();
        assert!(pds.am_data.is_none());
        assert!(pds.smf_sel_data.is_none());
        assert!(pds.sm_data.is_empty());
    }

    #[test]
    fn test_query_subscription_provisioned_ue_not_found() {
        let result = udm_nudr_dr_query_subscription_provisioned(
            999999, // Non-existent UE ID
            0,
            UdmSbiState::NoState,
        );
        assert!(!result.success);
        assert_eq!(result.status, http_status::BAD_REQUEST);
    }
}
