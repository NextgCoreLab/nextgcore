//! GMM Message Handling
//!
//! Port of src/amf/gmm-handler.c - GMM message handling functions for 5G NAS

use crate::context::{
    AmfUe, RanUe, PlmnId, Guti5gs, UeSecurityCapability,
    OGS_NAS_KSI_NO_KEY_IS_AVAILABLE,
};
use crate::gmm_build::{GmmCause, mobile_identity_type, registration_type};

// ============================================================================
// Constants
// ============================================================================

/// Minimum SUCI length
pub const OGS_NAS_5GS_MOBILE_IDENTITY_SUCI_MIN_SIZE: usize = 8;

/// Protection scheme IDs
pub mod protection_scheme {
    pub const NULL: u8 = 0;
    pub const PROFILE_A: u8 = 1;
    pub const PROFILE_B: u8 = 2;
}

/// SUPI format
pub mod supi_format {
    pub const IMSI: u8 = 0;
    pub const NETWORK_SPECIFIC: u8 = 1;
}

/// Service type
pub mod service_type {
    pub const SIGNALLING: u8 = 0;
    pub const DATA: u8 = 1;
    pub const MOBILE_TERMINATED_SERVICES: u8 = 2;
    pub const EMERGENCY_SERVICES: u8 = 3;
    pub const EMERGENCY_SERVICES_FALLBACK: u8 = 4;
    pub const HIGH_PRIORITY_ACCESS: u8 = 5;
}

// ============================================================================
// Registration Request Handling
// ============================================================================

/// Registration request cleartext presence mask
const REGISTRATION_CLEARTEXT_PRESENT: u64 = 
    (1 << 0) |  // UE_SECURITY_CAPABILITY
    (1 << 1) |  // UE_STATUS
    (1 << 2) |  // EPS_NAS_MESSAGE_CONTAINER
    (1 << 3) |  // NAS_MESSAGE_CONTAINER
    (1 << 4);   // ADDITIONAL_GUTI

/// Parsed registration request
#[derive(Debug, Clone, Default)]
pub struct RegistrationRequest {
    /// Registration type
    pub registration_type: u8,
    /// ngKSI TSC
    pub tsc: u8,
    /// ngKSI value
    pub ksi: u8,
    /// Mobile identity type
    pub mobile_identity_type: u8,
    /// SUCI (if present)
    pub suci: Option<String>,
    /// Old GUTI (if present)
    pub old_guti: Option<Guti5gs>,
    /// Home PLMN ID
    pub home_plmn_id: Option<PlmnId>,
    /// UE security capability
    pub ue_security_capability: Option<UeSecurityCapability>,
    /// Presence mask
    pub presencemask: u64,
    /// NAS message container present
    pub nas_message_container_present: bool,
}

/// Handle registration request
pub fn handle_registration_request(
    amf_ue: &mut AmfUe,
    ran_ue: &RanUe,
    request: &RegistrationRequest,
    is_initial_ue_message: bool,
    integrity_protected: bool,
) -> GmmCause {
    // Check for non-cleartext IEs in initial UE message
    if is_initial_ue_message && (request.presencemask & !REGISTRATION_CLEARTEXT_PRESENT) != 0 {
        log::error!("Non cleartext IEs included in initial UE message");
        return GmmCause::SemanticallyIncorrectMessage;
    }

    // Check NAS container without integrity protection
    if !integrity_protected && request.nas_message_container_present {
        log::error!("NAS container present without integrity protection");
        return GmmCause::SemanticallyIncorrectMessage;
    }

    // Process mobile identity
    match request.mobile_identity_type {
        mobile_identity_type::SUCI => {
            if let Some(ref suci) = request.suci {
                amf_ue.suci = Some(suci.clone());
                log::info!("[{}] SUCI received", suci);
            }
            if let Some(ref plmn_id) = request.home_plmn_id {
                amf_ue.home_plmn_id = plmn_id.clone();
            }
        }
        mobile_identity_type::GUTI => {
            if let Some(ref guti) = request.old_guti {
                amf_ue.old_guti = guti.clone();
                log::info!("5G-S_GUTI[AMF_ID:0x{:x},M_TMSI:0x{:x}]",
                    (guti.amf_region_id as u32) << 16 | (guti.amf_set_id as u32) << 6 | guti.amf_pointer as u32,
                    guti.tmsi);
            }
        }
        _ => {
            log::error!("Unknown mobile identity type: {}", request.mobile_identity_type);
        }
    }

    // Set registration type
    amf_ue.registration_type = request.registration_type;
    amf_ue.nas_message_type = crate::gmm_build::message_type::REGISTRATION_REQUEST;

    // Handle ngKSI
    amf_ue.nas_ue_tsc = request.tsc;
    amf_ue.nas_ue_ksi = request.ksi;
    
    if amf_ue.nas_ue_ksi < OGS_NAS_KSI_NO_KEY_IS_AVAILABLE {
        amf_ue.nas_tsc = amf_ue.nas_ue_tsc;
        amf_ue.nas_ksi = amf_ue.nas_ue_ksi;
    }

    // Clear timers and messages for new registration
    amf_ue.clear_paging_info();
    amf_ue.clear_timers();

    // Copy TAI/CGI from RAN UE
    amf_ue.nr_tai = ran_ue.saved_nr_tai.clone();
    amf_ue.nr_cgi = ran_ue.saved_nr_cgi.clone();
    amf_ue.gnb_ostream_id = ran_ue.gnb_ostream_id;

    // Set UE security capability
    if let Some(ref sec_cap) = request.ue_security_capability {
        amf_ue.ue_security_capability = sec_cap.clone();
    }

    // Generate new GUTI
    amf_ue.generate_new_guti();

    GmmCause::RequestAccepted
}

// ============================================================================
// Service Request Handling
// ============================================================================

/// Parsed service request
#[derive(Debug, Clone, Default)]
pub struct ServiceRequest {
    /// ngKSI TSC
    pub tsc: u8,
    /// ngKSI value
    pub ksi: u8,
    /// Service type
    pub service_type: u8,
    /// 5G-S-TMSI
    pub tmsi: Option<u32>,
    /// Uplink data status
    pub uplink_data_status: Option<u16>,
    /// PDU session status
    pub pdu_session_status: Option<u16>,
    /// Allowed PDU session status
    pub allowed_pdu_session_status: Option<u16>,
    /// Presence mask
    pub presencemask: u64,
    /// NAS message container present
    pub nas_message_container_present: bool,
}

/// Service request cleartext presence mask
const SERVICE_CLEARTEXT_PRESENT: u64 = 1 << 0; // NAS_MESSAGE_CONTAINER

/// Handle service request
pub fn handle_service_request(
    amf_ue: &mut AmfUe,
    ran_ue: &RanUe,
    request: &ServiceRequest,
    is_initial_ue_message: bool,
    integrity_protected: bool,
) -> GmmCause {
    // Check for non-cleartext IEs in initial UE message
    if is_initial_ue_message && (request.presencemask & !SERVICE_CLEARTEXT_PRESENT) != 0 {
        log::error!("Non cleartext IEs included in initial UE message");
        return GmmCause::SemanticallyIncorrectMessage;
    }

    // Check NAS container without integrity protection
    if !integrity_protected && request.nas_message_container_present {
        log::error!("NAS container present without integrity protection");
        return GmmCause::SemanticallyIncorrectMessage;
    }

    // Set message type
    amf_ue.nas_message_type = crate::gmm_build::message_type::SERVICE_REQUEST;

    // Handle ngKSI
    amf_ue.nas_ue_tsc = request.tsc;
    amf_ue.nas_ue_ksi = request.ksi;
    
    if amf_ue.nas_ue_ksi < OGS_NAS_KSI_NO_KEY_IS_AVAILABLE {
        amf_ue.nas_tsc = amf_ue.nas_ue_tsc;
        amf_ue.nas_ksi = amf_ue.nas_ue_ksi;
    }

    // Clear timers
    amf_ue.clear_timers();

    // Copy TAI/CGI from RAN UE
    amf_ue.nr_tai = ran_ue.saved_nr_tai.clone();
    amf_ue.nr_cgi = ran_ue.saved_nr_cgi.clone();
    amf_ue.gnb_ostream_id = ran_ue.gnb_ostream_id;

    // Handle PDU session status
    if let Some(psi) = request.pdu_session_status {
        amf_ue.pdu_session_status_present = true;
        amf_ue.pdu_session_status = psi;
    } else {
        amf_ue.pdu_session_status_present = false;
    }

    // Handle uplink data status
    if let Some(status) = request.uplink_data_status {
        amf_ue.uplink_data_status_present = true;
        amf_ue.uplink_data_status = status;
    } else {
        amf_ue.uplink_data_status_present = false;
    }

    GmmCause::RequestAccepted
}

// ============================================================================
// Deregistration Request Handling
// ============================================================================

/// Parsed deregistration request
#[derive(Debug, Clone, Default)]
pub struct DeregistrationRequest {
    /// Switch off flag
    pub switch_off: bool,
    /// Re-registration required
    pub re_registration_required: bool,
    /// Access type
    pub access_type: u8,
    /// ngKSI TSC
    pub tsc: u8,
    /// ngKSI value
    pub ksi: u8,
}

/// Handle deregistration request
pub fn handle_deregistration_request(
    amf_ue: &mut AmfUe,
    request: &DeregistrationRequest,
) -> Result<(), GmmCause> {
    // Set message type
    amf_ue.nas_message_type = crate::gmm_build::message_type::DEREGISTRATION_REQUEST_FROM_UE;

    // Handle ngKSI
    amf_ue.nas_ue_tsc = request.tsc;
    amf_ue.nas_ue_ksi = request.ksi;
    
    if amf_ue.nas_ue_ksi < OGS_NAS_KSI_NO_KEY_IS_AVAILABLE {
        amf_ue.nas_tsc = amf_ue.nas_ue_tsc;
        amf_ue.nas_ksi = amf_ue.nas_ue_ksi;
    }

    // Store switch-off flag
    amf_ue.switch_off = request.switch_off;

    if request.switch_off {
        log::debug!("UE switch-off deregistration");
    }

    log::info!("[{}] Deregistration request", amf_ue.supi.as_deref().unwrap_or("Unknown"));

    Ok(())
}

// ============================================================================
// Authentication Response Handling
// ============================================================================

/// Parsed authentication response
#[derive(Debug, Clone, Default)]
pub struct AuthenticationResponse {
    /// Authentication response parameter (RES*)
    pub res_star: Vec<u8>,
}

/// Handle authentication response
pub fn handle_authentication_response(
    amf_ue: &mut AmfUe,
    response: &AuthenticationResponse,
) -> Result<(), GmmCause> {
    log::debug!("[{}] Authentication response", amf_ue.suci.as_deref().unwrap_or("Unknown"));

    // Clear T3560 timer
    amf_ue.t3560_running = false;

    // Validate response length
    if response.res_star.len() != 16 {
        log::error!("Invalid RES* length: {}", response.res_star.len());
        return Err(GmmCause::MacFailure);
    }

    // Compute HXRES* and compare
    let hxres_star = compute_hxres_star(&amf_ue.rand, &response.res_star);
    
    if hxres_star != amf_ue.hxres_star {
        log::error!("HXRES* mismatch - MAC failure");
        return Err(GmmCause::MacFailure);
    }

    // Store XRES*
    amf_ue.xres_star.copy_from_slice(&response.res_star);

    Ok(())
}

/// Compute HXRES* from RAND and RES*
fn compute_hxres_star(rand: &[u8; 16], res_star: &[u8]) -> [u8; 16] {
    use sha2::{Sha256, Digest};
    
    let mut hasher = Sha256::new();
    hasher.update(rand);
    hasher.update(res_star);
    let result = hasher.finalize();
    
    let mut hxres_star = [0u8; 16];
    hxres_star.copy_from_slice(&result[16..32]);
    hxres_star
}

// ============================================================================
// Identity Response Handling
// ============================================================================

/// Parsed identity response
#[derive(Debug, Clone, Default)]
pub struct IdentityResponse {
    /// Mobile identity type
    pub mobile_identity_type: u8,
    /// SUCI (if present)
    pub suci: Option<String>,
    /// Home PLMN ID
    pub home_plmn_id: Option<PlmnId>,
}

/// Handle identity response
pub fn handle_identity_response(
    amf_ue: &mut AmfUe,
    response: &IdentityResponse,
) -> GmmCause {
    match response.mobile_identity_type {
        mobile_identity_type::SUCI => {
            if let Some(ref suci) = response.suci {
                amf_ue.suci = Some(suci.clone());
                log::info!("[{}] SUCI from identity response", suci);
            }
            if let Some(ref plmn_id) = response.home_plmn_id {
                amf_ue.home_plmn_id = plmn_id.clone();
            }
        }
        _ => {
            log::error!("Unsupported identity type: {}", response.mobile_identity_type);
            return GmmCause::SemanticallyIncorrectMessage;
        }
    }

    GmmCause::RequestAccepted
}

// ============================================================================
// Security Mode Complete Handling
// ============================================================================

/// Parsed security mode complete
#[derive(Debug, Clone, Default)]
pub struct SecurityModeComplete {
    /// IMEISV (if present)
    pub imeisv: Option<String>,
    /// NAS message container present
    pub nas_message_container_present: bool,
    /// NAS message container
    pub nas_message_container: Vec<u8>,
}

/// Handle security mode complete
pub fn handle_security_mode_complete(
    amf_ue: &mut AmfUe,
    complete: &SecurityModeComplete,
) -> GmmCause {
    // NAS message container is required
    if !complete.nas_message_container_present {
        log::error!("No NAS message container in security mode complete");
        return GmmCause::MessageNotCompatibleWithTheProtocolState;
    }

    // Store IMEISV if present
    if let Some(ref imeisv) = complete.imeisv {
        amf_ue.imeisv = Some(imeisv.clone());
        amf_ue.pei = Some(format!("imeisv-{}", imeisv));
    }

    GmmCause::RequestAccepted
}

// ============================================================================
// UL NAS Transport Handling
// ============================================================================

/// Payload container types
pub mod payload_container_type {
    pub const N1_SM_INFORMATION: u8 = 0x01;
    pub const SMS: u8 = 0x02;
    pub const LPP: u8 = 0x03;
    pub const SOR_TRANSPARENT_CONTAINER: u8 = 0x04;
    pub const UE_POLICY_CONTAINER: u8 = 0x05;
    pub const UE_PARAMETERS_UPDATE: u8 = 0x06;
    pub const MULTIPLE_PAYLOADS: u8 = 0x0f;
}

/// Parsed UL NAS transport
#[derive(Debug, Clone, Default)]
pub struct UlNasTransport {
    /// Payload container type
    pub payload_container_type: u8,
    /// Payload container
    pub payload_container: Vec<u8>,
    /// PDU session ID
    pub pdu_session_id: Option<u8>,
    /// Request type
    pub request_type: Option<u8>,
    /// S-NSSAI
    pub s_nssai: Option<crate::context::SNssai>,
    /// DNN
    pub dnn: Option<String>,
}

/// Handle UL NAS transport
pub fn handle_ul_nas_transport(
    amf_ue: &mut AmfUe,
    _ran_ue: &RanUe,
    transport: &UlNasTransport,
) -> Result<(), GmmCause> {
    // Validate payload container type
    if transport.payload_container_type == 0 {
        log::error!("No payload container type");
        return Err(GmmCause::InvalidMandatoryInformation);
    }

    // Validate payload container
    if transport.payload_container.is_empty() {
        log::error!("Empty payload container");
        return Err(GmmCause::InvalidMandatoryInformation);
    }

    // Validate PDU session ID
    let psi = transport.pdu_session_id.ok_or_else(|| {
        log::error!("No PDU session ID");
        GmmCause::InvalidMandatoryInformation
    })?;

    if psi == 0 {
        log::error!("PDU session identity is unassigned");
        return Err(GmmCause::InvalidMandatoryInformation);
    }

    match transport.payload_container_type {
        payload_container_type::N1_SM_INFORMATION => {
            // Handle N1 SM information
            log::debug!("[{}] UL NAS Transport - N1 SM Information, PSI={}", 
                amf_ue.supi.as_deref().unwrap_or("Unknown"), psi);
            
            // Store payload for session handling
            amf_ue.pending_n1_sm_msg = Some(transport.payload_container.clone());
            amf_ue.pending_psi = Some(psi);
        }
        _ => {
            log::error!("Unknown payload container type: {}", transport.payload_container_type);
            return Err(GmmCause::MessageTypeNonExistentOrNotImplemented);
        }
    }

    Ok(())
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Check if registration request is from old AMF (for context transfer)
pub fn registration_request_from_old_amf(
    amf_ue: &AmfUe,
    served_guami: &[crate::context::Guami],
) -> bool {
    // Check if we have an old GUTI
    if amf_ue.old_guti.tmsi == 0 {
        return false;
    }

    // Check for all-zero GUTI (invalid)
    if amf_ue.old_guti.amf_region_id == 0 
        && amf_ue.old_guti.amf_set_id == 0
        && amf_ue.old_guti.plmn_id.mcc1 == 0
        && amf_ue.old_guti.plmn_id.mcc2 == 0
        && amf_ue.old_guti.plmn_id.mcc3 == 0
    {
        return false;
    }

    // Check if GUTI matches any served GUAMI
    for guami in served_guami {
        if guami.plmn_id == amf_ue.old_guti.plmn_id
            && guami.amf_id.region == amf_ue.old_guti.amf_region_id
            && guami.amf_id.set == amf_ue.old_guti.amf_set_id
            && guami.amf_id.pointer == amf_ue.old_guti.amf_pointer
        {
            return false; // GUTI is from this AMF
        }
    }

    log::info!("Serving AMF changed - context transfer needed");
    true
}

/// Parse SUCI from mobile identity buffer
pub fn parse_suci(buffer: &[u8]) -> Option<(String, PlmnId)> {
    if buffer.len() < OGS_NAS_5GS_MOBILE_IDENTITY_SUCI_MIN_SIZE {
        return None;
    }

    // Extract PLMN ID (bytes 1-3)
    let plmn_id = PlmnId {
        mcc1: buffer[1] & 0x0f,
        mcc2: (buffer[1] >> 4) & 0x0f,
        mcc3: buffer[2] & 0x0f,
        mnc3: (buffer[2] >> 4) & 0x0f,
        mnc1: buffer[3] & 0x0f,
        mnc2: (buffer[3] >> 4) & 0x0f,
    };

    // Build SUCI string (simplified)
    let suci = format!(
        "suci-0-{}{}{}-{}{}{}-0-0-0",
        plmn_id.mcc1, plmn_id.mcc2, plmn_id.mcc3,
        plmn_id.mnc1, plmn_id.mnc2,
        if plmn_id.mnc3 != 0xf { format!("{}", plmn_id.mnc3) } else { String::new() }
    );

    Some((suci, plmn_id))
}

/// Parse GUTI from mobile identity buffer
pub fn parse_guti(buffer: &[u8]) -> Option<Guti5gs> {
    if buffer.len() < 11 {
        return None;
    }

    let plmn_id = PlmnId {
        mcc1: buffer[1] & 0x0f,
        mcc2: (buffer[1] >> 4) & 0x0f,
        mcc3: buffer[2] & 0x0f,
        mnc3: (buffer[2] >> 4) & 0x0f,
        mnc1: buffer[3] & 0x0f,
        mnc2: (buffer[3] >> 4) & 0x0f,
    };

    let amf_region_id = buffer[4];
    let amf_set_id = ((buffer[5] as u16) << 2) | ((buffer[6] >> 6) as u16);
    let amf_pointer = buffer[6] & 0x3f;
    let tmsi = ((buffer[7] as u32) << 24)
        | ((buffer[8] as u32) << 16)
        | ((buffer[9] as u32) << 8)
        | (buffer[10] as u32);

    Some(Guti5gs {
        plmn_id,
        amf_region_id,
        amf_set_id,
        amf_pointer,
        tmsi,
    })
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::{Tai5gs, NrCgi};

    fn create_test_amf_ue() -> AmfUe {
        AmfUe {
            id: 1,
            ran_ue_id: 1,
            ..Default::default()
        }
    }

    fn create_test_ran_ue() -> RanUe {
        RanUe {
            id: 1,
            gnb_id: 1,
            ran_ue_ngap_id: 1,
            amf_ue_ngap_id: 1,
            saved_nr_tai: Tai5gs {
                plmn_id: PlmnId::new("001", "01"),
                tac: 1,
            },
            saved_nr_cgi: NrCgi {
                plmn_id: PlmnId::new("001", "01"),
                cell_id: 1,
            },
            gnb_ostream_id: 0,
            ..Default::default()
        }
    }

    #[test]
    fn test_handle_registration_request_initial() {
        let mut amf_ue = create_test_amf_ue();
        let ran_ue = create_test_ran_ue();
        
        let request = RegistrationRequest {
            registration_type: registration_type::INITIAL,
            tsc: 0,
            ksi: 1,
            mobile_identity_type: mobile_identity_type::SUCI,
            suci: Some("suci-0-001-01-0-0-0-0000000001".to_string()),
            home_plmn_id: Some(PlmnId::new("001", "01")),
            presencemask: 0,
            ..Default::default()
        };

        let result = handle_registration_request(
            &mut amf_ue, &ran_ue, &request, true, false
        );

        assert_eq!(result, GmmCause::RequestAccepted);
        assert!(amf_ue.suci.is_some());
        assert_eq!(amf_ue.registration_type, registration_type::INITIAL);
    }

    #[test]
    fn test_handle_registration_request_with_guti() {
        let mut amf_ue = create_test_amf_ue();
        let ran_ue = create_test_ran_ue();
        
        let request = RegistrationRequest {
            registration_type: registration_type::MOBILITY_UPDATING,
            tsc: 0,
            ksi: 2,
            mobile_identity_type: mobile_identity_type::GUTI,
            old_guti: Some(Guti5gs {
                plmn_id: PlmnId::new("001", "01"),
                amf_region_id: 1,
                amf_set_id: 1,
                amf_pointer: 1,
                tmsi: 0x12345678,
            }),
            presencemask: 0,
            ..Default::default()
        };

        let result = handle_registration_request(
            &mut amf_ue, &ran_ue, &request, true, false
        );

        assert_eq!(result, GmmCause::RequestAccepted);
        assert_eq!(amf_ue.old_guti.tmsi, 0x12345678);
    }

    #[test]
    fn test_handle_registration_request_non_cleartext_rejected() {
        let mut amf_ue = create_test_amf_ue();
        let ran_ue = create_test_ran_ue();
        
        let request = RegistrationRequest {
            registration_type: registration_type::INITIAL,
            presencemask: 0xFFFF, // Non-cleartext IEs
            ..Default::default()
        };

        let result = handle_registration_request(
            &mut amf_ue, &ran_ue, &request, true, false
        );

        assert_eq!(result, GmmCause::SemanticallyIncorrectMessage);
    }

    #[test]
    fn test_handle_service_request() {
        let mut amf_ue = create_test_amf_ue();
        let ran_ue = create_test_ran_ue();
        
        let request = ServiceRequest {
            tsc: 0,
            ksi: 1,
            service_type: service_type::DATA,
            pdu_session_status: Some(0x0020), // PSI 5
            presencemask: 0,
            ..Default::default()
        };

        let result = handle_service_request(
            &mut amf_ue, &ran_ue, &request, true, false
        );

        assert_eq!(result, GmmCause::RequestAccepted);
        assert!(amf_ue.pdu_session_status_present);
    }

    #[test]
    fn test_handle_deregistration_request() {
        let mut amf_ue = create_test_amf_ue();
        amf_ue.supi = Some("imsi-001010000000001".to_string());
        
        let request = DeregistrationRequest {
            switch_off: true,
            re_registration_required: false,
            access_type: 1,
            tsc: 0,
            ksi: 1,
        };

        let result = handle_deregistration_request(&mut amf_ue, &request);

        assert!(result.is_ok());
        assert!(amf_ue.switch_off);
    }

    #[test]
    fn test_handle_identity_response() {
        let mut amf_ue = create_test_amf_ue();
        
        let response = IdentityResponse {
            mobile_identity_type: mobile_identity_type::SUCI,
            suci: Some("suci-0-001-01-0-0-0-0000000001".to_string()),
            home_plmn_id: Some(PlmnId::new("001", "01")),
        };

        let result = handle_identity_response(&mut amf_ue, &response);

        assert_eq!(result, GmmCause::RequestAccepted);
        assert!(amf_ue.suci.is_some());
    }

    #[test]
    fn test_handle_security_mode_complete() {
        let mut amf_ue = create_test_amf_ue();
        
        let complete = SecurityModeComplete {
            imeisv: Some("3512340052143210".to_string()),
            nas_message_container_present: true,
            nas_message_container: vec![0x7e, 0x00, 0x41],
        };

        let result = handle_security_mode_complete(&mut amf_ue, &complete);

        assert_eq!(result, GmmCause::RequestAccepted);
        assert!(amf_ue.imeisv.is_some());
        assert!(amf_ue.pei.is_some());
    }

    #[test]
    fn test_handle_security_mode_complete_no_container() {
        let mut amf_ue = create_test_amf_ue();
        
        let complete = SecurityModeComplete {
            nas_message_container_present: false,
            ..Default::default()
        };

        let result = handle_security_mode_complete(&mut amf_ue, &complete);

        assert_eq!(result, GmmCause::MessageNotCompatibleWithTheProtocolState);
    }

    #[test]
    fn test_handle_ul_nas_transport() {
        let mut amf_ue = create_test_amf_ue();
        let ran_ue = create_test_ran_ue();
        
        let transport = UlNasTransport {
            payload_container_type: payload_container_type::N1_SM_INFORMATION,
            payload_container: vec![0x2e, 0x01, 0xc1],
            pdu_session_id: Some(5),
            ..Default::default()
        };

        let result = handle_ul_nas_transport(&mut amf_ue, &ran_ue, &transport);

        assert!(result.is_ok());
        assert!(amf_ue.pending_n1_sm_msg.is_some());
        assert_eq!(amf_ue.pending_psi, Some(5));
    }

    #[test]
    fn test_handle_ul_nas_transport_no_psi() {
        let mut amf_ue = create_test_amf_ue();
        let ran_ue = create_test_ran_ue();
        
        let transport = UlNasTransport {
            payload_container_type: payload_container_type::N1_SM_INFORMATION,
            payload_container: vec![0x2e, 0x01, 0xc1],
            pdu_session_id: None,
            ..Default::default()
        };

        let result = handle_ul_nas_transport(&mut amf_ue, &ran_ue, &transport);

        assert!(result.is_err());
    }

    #[test]
    fn test_parse_guti() {
        let buffer = vec![
            0xf2, // Type (GUTI)
            0x10, 0xf0, 0x10, // MCC=001, MNC=01
            0x01, // AMF Region ID
            0x00, 0x41, // AMF Set ID + Pointer
            0x12, 0x34, 0x56, 0x78, // 5G-TMSI
        ];

        let guti = parse_guti(&buffer);
        assert!(guti.is_some());
        
        let guti = guti.unwrap();
        assert_eq!(guti.amf_region_id, 0x01);
        assert_eq!(guti.tmsi, 0x12345678);
    }

    #[test]
    fn test_registration_request_from_old_amf() {
        let mut amf_ue = create_test_amf_ue();
        amf_ue.old_guti = Guti5gs {
            plmn_id: PlmnId::new("002", "02"),
            amf_region_id: 2,
            amf_set_id: 2,
            amf_pointer: 2,
            tmsi: 0x12345678,
        };

        let served_guami = vec![
            crate::context::Guami {
                plmn_id: PlmnId::new("001", "01"),
                amf_id: crate::context::AmfId {
                    region: 1,
                    set: 1,
                    pointer: 1,
                },
            },
        ];

        // GUTI doesn't match served GUAMI, so it's from old AMF
        assert!(registration_request_from_old_amf(&amf_ue, &served_guami));
    }

    #[test]
    fn test_registration_request_from_same_amf() {
        let mut amf_ue = create_test_amf_ue();
        amf_ue.old_guti = Guti5gs {
            plmn_id: PlmnId::new("001", "01"),
            amf_region_id: 1,
            amf_set_id: 1,
            amf_pointer: 1,
            tmsi: 0x12345678,
        };

        let served_guami = vec![
            crate::context::Guami {
                plmn_id: PlmnId::new("001", "01"),
                amf_id: crate::context::AmfId {
                    region: 1,
                    set: 1,
                    pointer: 1,
                },
            },
        ];

        // GUTI matches served GUAMI, so it's from same AMF
        assert!(!registration_request_from_old_amf(&amf_ue, &served_guami));
    }

    #[test]
    fn test_compute_hxres_star() {
        let rand = [0u8; 16];
        let res_star = [1u8; 16];
        
        let hxres_star = compute_hxres_star(&rand, &res_star);
        
        // Just verify it produces a 16-byte result
        assert_eq!(hxres_star.len(), 16);
    }
}
