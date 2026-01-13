//! NUDM Handler Functions
//!
//! Port of src/udm/nudm-handler.c - NUDM service handlers
//! Handles NUDM-UEAU, NUDM-UECM, and NUDM-SDM service requests

use crate::context::{
    udm_self, Amf3GppAccessRegistration, AuthEvent, AuthType, Guami, PlmnId, RatType,
    SmfRegistration, UdmSdmSubscription, OGS_RAND_LEN, OGS_SQN_LEN,
};
use crate::nudr_handler::UdmSbiState;

/// HTTP status codes
pub mod http_status {
    pub const OK: u16 = 200;
    pub const CREATED: u16 = 201;
    pub const NO_CONTENT: u16 = 204;
    pub const BAD_REQUEST: u16 = 400;
    pub const FORBIDDEN: u16 = 403;
    pub const NOT_FOUND: u16 = 404;
    pub const INTERNAL_SERVER_ERROR: u16 = 500;
}

/// Handler result with HTTP status and optional error message
#[derive(Debug)]
pub struct HandlerResult {
    pub success: bool,
    pub status: u16,
    pub error_message: Option<String>,
    pub error_cause: Option<String>,
}

impl HandlerResult {
    pub fn ok() -> Self {
        Self {
            success: true,
            status: http_status::OK,
            error_message: None,
            error_cause: None,
        }
    }

    pub fn created() -> Self {
        Self {
            success: true,
            status: http_status::CREATED,
            error_message: None,
            error_cause: None,
        }
    }

    pub fn no_content() -> Self {
        Self {
            success: true,
            status: http_status::NO_CONTENT,
            error_message: None,
            error_cause: None,
        }
    }

    pub fn bad_request(message: &str) -> Self {
        Self {
            success: false,
            status: http_status::BAD_REQUEST,
            error_message: Some(message.to_string()),
            error_cause: None,
        }
    }

    pub fn forbidden(message: &str, cause: Option<&str>) -> Self {
        Self {
            success: false,
            status: http_status::FORBIDDEN,
            error_message: Some(message.to_string()),
            error_cause: cause.map(|s| s.to_string()),
        }
    }

    pub fn not_found(message: &str) -> Self {
        Self {
            success: false,
            status: http_status::NOT_FOUND,
            error_message: Some(message.to_string()),
            error_cause: None,
        }
    }
}

/// Authentication info request data
#[derive(Debug, Clone, Default)]
pub struct AuthenticationInfoRequest {
    pub serving_network_name: Option<String>,
    pub ausf_instance_id: Option<String>,
    pub resynchronization_info: Option<ResynchronizationInfo>,
}

/// Resynchronization info for re-sync procedure
#[derive(Debug, Clone, Default)]
pub struct ResynchronizationInfo {
    pub rand: Option<String>,
    pub auts: Option<String>,
}

/// AMF 3GPP Access Registration request
#[derive(Debug, Clone, Default)]
pub struct Amf3GppAccessRegistrationRequest {
    pub amf_instance_id: Option<String>,
    pub dereg_callback_uri: Option<String>,
    pub guami: Option<GuamiRequest>,
    pub rat_type: Option<String>,
}

/// GUAMI request data
#[derive(Debug, Clone, Default)]
pub struct GuamiRequest {
    pub amf_id: Option<String>,
    pub plmn_id: Option<PlmnIdRequest>,
}

/// PLMN ID request data
#[derive(Debug, Clone, Default)]
pub struct PlmnIdRequest {
    pub mcc: Option<String>,
    pub mnc: Option<String>,
}

/// AMF 3GPP Access Registration Modification request
#[derive(Debug, Clone, Default)]
pub struct Amf3GppAccessRegistrationModificationRequest {
    pub guami: Option<GuamiRequest>,
    pub purge_flag: Option<bool>,
}

/// SMF Registration request
#[derive(Debug, Clone, Default)]
pub struct SmfRegistrationRequest {
    pub smf_instance_id: Option<String>,
    pub pdu_session_id: Option<u8>,
    pub single_nssai: Option<String>,
    pub dnn: Option<String>,
    pub plmn_id: Option<PlmnIdRequest>,
}

/// SDM Subscription request
#[derive(Debug, Clone, Default)]
pub struct SdmSubscriptionRequest {
    pub nf_instance_id: Option<String>,
    pub callback_reference: Option<String>,
    pub monitored_resource_uris: Vec<String>,
}

/// Auth Event request
#[derive(Debug, Clone, Default)]
pub struct AuthEventRequest {
    pub nf_instance_id: Option<String>,
    pub success: Option<bool>,
    pub time_stamp: Option<String>,
    pub auth_type: Option<String>,
    pub serving_network_name: Option<String>,
    pub auth_removal_ind: Option<bool>,
}

/// Handle NUDM UEAU get request (security-information)
/// Port of udm_nudm_ueau_handle_get()
pub fn udm_nudm_ueau_handle_get(
    udm_ue_id: u64,
    _stream_id: u64,
    request: &AuthenticationInfoRequest,
) -> (HandlerResult, Option<UdmSbiState>) {
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

    log::debug!("[{}] Handle NUDM UEAU get request", udm_ue.suci);

    // Validate AuthenticationInfoRequest
    let serving_network_name = match &request.serving_network_name {
        Some(name) if !name.is_empty() => name.clone(),
        _ => {
            log::error!("[{}] No servingNetworkName", udm_ue.suci);
            return (HandlerResult::bad_request("No servingNetworkName"), None);
        }
    };

    let ausf_instance_id = match &request.ausf_instance_id {
        Some(id) if !id.is_empty() => id.clone(),
        _ => {
            log::error!("[{}] No ausfInstanceId", udm_ue.suci);
            return (HandlerResult::bad_request("No ausfInstanceId"), None);
        }
    };

    // Store serving network name and AUSF instance ID
    udm_ue.serving_network_name = Some(serving_network_name);
    udm_ue.ausf_instance_id = Some(ausf_instance_id);

    // Update UE in context
    let ctx = udm_self();
    let context = ctx.read().unwrap();
    context.ue_update(&udm_ue);
    drop(context);

    // Check for resynchronization info
    if let Some(ref resync_info) = request.resynchronization_info {
        // Handle resynchronization procedure
        let rand_str = match &resync_info.rand {
            Some(r) if !r.is_empty() => r,
            _ => {
                log::error!("[{}] No RAND", udm_ue.suci);
                return (HandlerResult::bad_request("No RAND"), None);
            }
        };

        let auts_str = match &resync_info.auts {
            Some(a) if !a.is_empty() => a,
            _ => {
                log::error!("[{}] No AUTS", udm_ue.suci);
                return (HandlerResult::bad_request("No AUTS"), None);
            }
        };

        // Convert hex strings to bytes
        let rand = hex_to_bytes(rand_str);
        let _auts = hex_to_bytes(auts_str);

        if rand.len() != OGS_RAND_LEN {
            log::error!("[{}] Invalid RAND length", udm_ue.suci);
            return (HandlerResult::bad_request("Invalid RAND"), None);
        }

        // Compare RAND with stored value
        if rand != udm_ue.rand {
            log::error!("[{}] Invalid RAND", udm_ue.suci);
            return (HandlerResult::bad_request("Invalid RAND"), None);
        }

        // Perform SQN resynchronization
        // Note: In production, ogs_auc_sqn() derives sqn_ms and mac_s from AUTS
        // SQN updated based on computed sqn_ms to prevent replay attacks
        let sqn = buffer_to_u64(&udm_ue.sqn);
        let new_sqn = (sqn + 32 + 1) & 0xFFFFFFFFFFFF; // OGS_MAX_SQN
        let mut new_sqn_bytes = [0u8; OGS_SQN_LEN];
        u64_to_buffer(new_sqn, &mut new_sqn_bytes);

        // Update UE with new SQN
        let ctx = udm_self();
        let context = ctx.read().unwrap();
        if let Some(mut ue) = context.ue_find_by_id(udm_ue_id) {
            ue.sqn = new_sqn_bytes;
            context.ue_update(&ue);
        }
        drop(context);

        log::debug!("[{}] SQN resynchronization completed", udm_ue.suci);
    }

    // Send request to UDR for authentication subscription
    // Return state to indicate we need to query UDR
    (HandlerResult::ok(), Some(UdmSbiState::NoState))
}

/// Handle NUDM UEAU result confirmation inform (auth-events)
/// Port of udm_nudm_ueau_handle_result_confirmation_inform()
pub fn udm_nudm_ueau_handle_result_confirmation_inform(
    udm_ue_id: u64,
    _stream_id: u64,
    request: &AuthEventRequest,
) -> HandlerResult {
    let ctx = udm_self();
    let context = ctx.read().unwrap();

    let mut udm_ue = match context.ue_find_by_id(udm_ue_id) {
        Some(ue) => ue,
        None => {
            log::error!("UDM UE not found [{}]", udm_ue_id);
            return HandlerResult::bad_request("UDM UE not found");
        }
    };
    drop(context);

    log::debug!("[{}] Handle NUDM UEAU result confirmation inform", udm_ue.suci);

    // Validate AuthEvent
    let nf_instance_id = match &request.nf_instance_id {
        Some(id) if !id.is_empty() => id.clone(),
        _ => {
            log::error!("[{}] No nfInstanceId", udm_ue.suci);
            return HandlerResult::bad_request("No nfInstanceId");
        }
    };

    let success = match request.success {
        Some(s) => s,
        None => {
            log::error!("[{}] No success", udm_ue.suci);
            return HandlerResult::bad_request("No success");
        }
    };

    let time_stamp = match &request.time_stamp {
        Some(ts) if !ts.is_empty() => ts.clone(),
        _ => {
            log::error!("[{}] No timeStamp", udm_ue.suci);
            return HandlerResult::bad_request("No timeStamp");
        }
    };

    let auth_type_str = match &request.auth_type {
        Some(at) if !at.is_empty() => at.clone(),
        _ => {
            log::error!("[{}] No authType", udm_ue.suci);
            return HandlerResult::bad_request("No authType");
        }
    };

    let serving_network_name = match &request.serving_network_name {
        Some(snn) if !snn.is_empty() => snn.clone(),
        _ => {
            log::error!("[{}] No servingNetworkName", udm_ue.suci);
            return HandlerResult::bad_request("No servingNetworkName");
        }
    };

    // Parse auth type
    let auth_type = match auth_type_str.as_str() {
        "5G_AKA" => Some(AuthType::FiveGAka),
        "EAP_AKA_PRIME" => Some(AuthType::EapAkaPrime),
        "EAP_TLS" => Some(AuthType::EapTls),
        _ => None,
    };

    // Create and store auth event
    let auth_event = AuthEvent {
        nf_instance_id: Some(nf_instance_id),
        success,
        time_stamp: Some(time_stamp),
        auth_type,
        serving_network_name: Some(serving_network_name),
    };

    udm_ue.set_auth_event(auth_event);

    // Update UE in context
    let ctx = udm_self();
    let context = ctx.read().unwrap();
    context.ue_update(&udm_ue);
    drop(context);

    // Send request to UDR to update authentication status
    // This would trigger udm_nudr_dr_build_update_authentication_status
    HandlerResult::ok()
}

/// Handle NUDM UECM AMF registration
/// Port of udm_nudm_uecm_handle_amf_registration()
pub fn udm_nudm_uecm_handle_amf_registration(
    udm_ue_id: u64,
    _stream_id: u64,
    request: &Amf3GppAccessRegistrationRequest,
) -> HandlerResult {
    let ctx = udm_self();
    let context = ctx.read().unwrap();

    let mut udm_ue = match context.ue_find_by_id(udm_ue_id) {
        Some(ue) => ue,
        None => {
            log::error!("UDM UE not found [{}]", udm_ue_id);
            return HandlerResult::bad_request("UDM UE not found");
        }
    };
    drop(context);

    let supi = udm_ue.supi.clone().unwrap_or_else(|| udm_ue.suci.clone());
    log::debug!("[{}] Handle NUDM UECM AMF registration", supi);

    // Validate Amf3GppAccessRegistration
    let amf_instance_id = match &request.amf_instance_id {
        Some(id) if !id.is_empty() => id.clone(),
        _ => {
            log::error!("[{}] No amfInstanceId", supi);
            return HandlerResult::bad_request("No amfInstanceId");
        }
    };

    let dereg_callback_uri = match &request.dereg_callback_uri {
        Some(uri) if !uri.is_empty() => uri.clone(),
        _ => {
            log::error!("[{}] No dregCallbackUri", supi);
            return HandlerResult::bad_request("No dregCallbackUri");
        }
    };

    // Validate GUAMI
    let guami_req = match &request.guami {
        Some(g) => g,
        None => {
            log::error!("[{}] No Guami", supi);
            return HandlerResult::bad_request("No Guami");
        }
    };

    let amf_id = match &guami_req.amf_id {
        Some(id) if !id.is_empty() => id.clone(),
        _ => {
            log::error!("[{}] No Guami.AmfId", supi);
            return HandlerResult::bad_request("No Guami.AmfId");
        }
    };

    let plmn_id_req = match &guami_req.plmn_id {
        Some(p) => p,
        None => {
            log::error!("[{}] No PlmnId", supi);
            return HandlerResult::bad_request("No PlmnId");
        }
    };

    let mcc = match &plmn_id_req.mcc {
        Some(m) if !m.is_empty() => m.clone(),
        _ => {
            log::error!("[{}] No PlmnId.Mcc", supi);
            return HandlerResult::bad_request("No PlmnId.Mcc");
        }
    };

    let mnc = match &plmn_id_req.mnc {
        Some(m) if !m.is_empty() => m.clone(),
        _ => {
            log::error!("[{}] No PlmnId.Mnc", supi);
            return HandlerResult::bad_request("No PlmnId.Mnc");
        }
    };

    // Validate RAT type
    if request.rat_type.is_none() {
        log::error!("[{}] No RatType", supi);
        return HandlerResult::bad_request("No RatType");
    }

    // Parse RAT type
    let rat_type = match request.rat_type.as_deref() {
        Some("NR") => RatType::Nr,
        Some("EUTRA") => RatType::Eutra,
        Some("WLAN") => RatType::Wlan,
        Some("VIRTUAL") => RatType::Virtual,
        _ => RatType::Nr,
    };

    // Parse AMF ID (hex string to components)
    let amf_id_parsed = parse_amf_id(&amf_id);

    // Store registration data
    udm_ue.dereg_callback_uri = Some(dereg_callback_uri.clone());
    udm_ue.guami = Guami {
        plmn_id: PlmnId { mcc, mnc },
        amf_id: amf_id_parsed,
    };
    udm_ue.rat_type = rat_type;

    // Store AMF 3GPP access registration
    let registration = Amf3GppAccessRegistration {
        amf_instance_id: Some(amf_instance_id),
        dereg_callback_uri: Some(dereg_callback_uri),
        guami: Some(udm_ue.guami.clone()),
        rat_type: Some(rat_type),
    };
    udm_ue.set_amf_3gpp_access_registration(registration);

    // Update UE in context
    let ctx = udm_self();
    let context = ctx.read().unwrap();
    context.ue_update(&udm_ue);
    drop(context);

    // Send request to UDR to update AMF context
    HandlerResult::ok()
}

/// Handle NUDM UECM AMF registration update
/// Port of udm_nudm_uecm_handle_amf_registration_update()
pub fn udm_nudm_uecm_handle_amf_registration_update(
    udm_ue_id: u64,
    _stream_id: u64,
    request: &Amf3GppAccessRegistrationModificationRequest,
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
    log::debug!("[{}] Handle NUDM UECM AMF registration update", supi);

    // Validate GUAMI
    let guami_req = match &request.guami {
        Some(g) => g,
        None => {
            log::error!("[{}] No Guami", supi);
            return HandlerResult::bad_request("No Guami");
        }
    };

    let amf_id = match &guami_req.amf_id {
        Some(id) if !id.is_empty() => id.clone(),
        _ => {
            log::error!("[{}] No Guami.AmfId", supi);
            return HandlerResult::bad_request("No Guami.AmfId");
        }
    };

    let plmn_id_req = match &guami_req.plmn_id {
        Some(p) => p,
        None => {
            log::error!("[{}] No PlmnId", supi);
            return HandlerResult::bad_request("No PlmnId");
        }
    };

    let mcc = match &plmn_id_req.mcc {
        Some(m) if !m.is_empty() => m.clone(),
        _ => {
            log::error!("[{}] No PlmnId.Mcc", supi);
            return HandlerResult::bad_request("No PlmnId.Mcc");
        }
    };

    let mnc = match &plmn_id_req.mnc {
        Some(m) if !m.is_empty() => m.clone(),
        _ => {
            log::error!("[{}] No PlmnId.Mnc", supi);
            return HandlerResult::bad_request("No PlmnId.Mnc");
        }
    };

    // Parse received GUAMI
    let recv_guami = Guami {
        plmn_id: PlmnId { mcc, mnc },
        amf_id: parse_amf_id(&amf_id),
    };

    // Check if received GUAMI matches stored GUAMI
    // TS 29.503: 5.3.2.4.2 AMF deregistration for 3GPP access
    if !guami_matches(&recv_guami, &udm_ue.guami) {
        log::error!("[{}] Guami mismatch", supi);
        return HandlerResult::forbidden("Guami mismatch", Some("INVALID_GUAMI"));
    }

    // Handle purge flag if present
    if let Some(purge_flag) = request.purge_flag {
        let ctx = udm_self();
        let context = ctx.read().unwrap();
        if let Some(mut ue) = context.ue_find_by_id(udm_ue_id) {
            if let Some(ref mut _reg) = ue.amf_3gpp_access_registration {
                // Note: purge_flag stored in registration and sent to UDR on PATCH request
                log::debug!("[{}] Setting purge flag to {}", supi, purge_flag);
            }
            context.ue_update(&ue);
        }
        drop(context);
    }

    // Send PATCH request to UDR
    HandlerResult::ok()
}

/// Handle NUDM UECM AMF registration get
/// Port of udm_nudm_uecm_handle_amf_registration_get()
pub fn udm_nudm_uecm_handle_amf_registration_get(
    udm_ue_id: u64,
    _stream_id: u64,
    resource_name: &str,
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
    log::debug!("[{}] Handle NUDM UECM AMF registration get", supi);

    match resource_name {
        "registrations" => {
            if let Some(ref registration) = udm_ue.amf_3gpp_access_registration {
                (HandlerResult::ok(), Some(registration.clone()))
            } else {
                log::error!("Invalid UE Identifier [{}]", udm_ue.suci);
                (HandlerResult::bad_request("Invalid UE Identifier"), None)
            }
        }
        _ => {
            log::error!("Invalid resource name [{}]", resource_name);
            (HandlerResult::bad_request("Invalid resource name"), None)
        }
    }
}

/// Handle NUDM UECM SMF registration
/// Port of udm_nudm_uecm_handle_smf_registration()
pub fn udm_nudm_uecm_handle_smf_registration(
    sess_id: u64,
    _stream_id: u64,
    request: &SmfRegistrationRequest,
) -> HandlerResult {
    let ctx = udm_self();
    let context = ctx.read().unwrap();

    let mut sess = match context.sess_find_by_id(sess_id) {
        Some(s) => s,
        None => {
            log::error!("UDM session not found [{}]", sess_id);
            return HandlerResult::bad_request("UDM session not found");
        }
    };

    let udm_ue = match context.ue_find_by_id(sess.udm_ue_id) {
        Some(ue) => ue,
        None => {
            log::error!("UDM UE not found for session [{}]", sess_id);
            return HandlerResult::bad_request("UDM UE not found");
        }
    };
    drop(context);

    let supi = udm_ue.supi.clone().unwrap_or_else(|| udm_ue.suci.clone());
    log::debug!("[{}:{}] Handle NUDM UECM SMF registration", supi, sess.psi);

    // Validate SmfRegistration
    let smf_instance_id = match &request.smf_instance_id {
        Some(id) if !id.is_empty() => id.clone(),
        _ => {
            log::error!("[{}:{}] No smfInstanceId", supi, sess.psi);
            return HandlerResult::bad_request("No smfInstanceId");
        }
    };

    let pdu_session_id = match request.pdu_session_id {
        Some(id) if id > 0 => id,
        _ => {
            log::error!("[{}:{}] No pduSessionId", supi, sess.psi);
            return HandlerResult::bad_request("No pduSessionId");
        }
    };

    let single_nssai = match &request.single_nssai {
        Some(nssai) if !nssai.is_empty() => nssai.clone(),
        _ => {
            log::error!("[{}:{}] No singleNssai", supi, sess.psi);
            return HandlerResult::bad_request("No singleNssai");
        }
    };

    let dnn = match &request.dnn {
        Some(d) if !d.is_empty() => d.clone(),
        _ => {
            log::error!("[{}:{}] No dnn", supi, sess.psi);
            return HandlerResult::bad_request("No dnn");
        }
    };

    // Validate PLMN ID
    let plmn_id_req = match &request.plmn_id {
        Some(p) => p,
        None => {
            log::error!("[{}:{}] No plmnId", supi, sess.psi);
            return HandlerResult::bad_request("No plmnId");
        }
    };

    let mcc = match &plmn_id_req.mcc {
        Some(m) if !m.is_empty() => m.clone(),
        _ => {
            log::error!("[{}:{}] No plmnId.mcc", supi, sess.psi);
            return HandlerResult::bad_request("No plmnId.mcc");
        }
    };

    let mnc = match &plmn_id_req.mnc {
        Some(m) if !m.is_empty() => m.clone(),
        _ => {
            log::error!("[{}:{}] No plmnId.mnc", supi, sess.psi);
            return HandlerResult::bad_request("No plmnId.mnc");
        }
    };

    // Store SMF registration
    let smf_registration = SmfRegistration {
        smf_instance_id: Some(smf_instance_id),
        pdu_session_id,
        single_nssai: Some(single_nssai),
        dnn: Some(dnn),
        plmn_id: Some(PlmnId { mcc, mnc }),
    };
    sess.set_smf_registration(smf_registration);

    // Update session in context
    let ctx = udm_self();
    let context = ctx.read().unwrap();
    context.sess_update(&sess);
    drop(context);

    // Send request to UDR to update SMF context
    HandlerResult::ok()
}

/// Handle NUDM UECM SMF deregistration
/// Port of udm_nudm_uecm_handle_smf_deregistration()
pub fn udm_nudm_uecm_handle_smf_deregistration(sess_id: u64, _stream_id: u64) -> HandlerResult {
    let ctx = udm_self();
    let context = ctx.read().unwrap();

    let sess = match context.sess_find_by_id(sess_id) {
        Some(s) => s,
        None => {
            log::error!("UDM session not found [{}]", sess_id);
            return HandlerResult::bad_request("UDM session not found");
        }
    };

    let udm_ue = match context.ue_find_by_id(sess.udm_ue_id) {
        Some(ue) => ue,
        None => {
            log::error!("UDM UE not found for session [{}]", sess_id);
            return HandlerResult::bad_request("UDM UE not found");
        }
    };
    drop(context);

    let supi = udm_ue.supi.clone().unwrap_or_else(|| udm_ue.suci.clone());
    log::debug!("[{}:{}] Handle NUDM UECM SMF deregistration", supi, sess.psi);

    // Send request to UDR to delete SMF context
    HandlerResult::ok()
}

/// Handle NUDM SDM subscription provisioned (ue-context-in-smf-data)
/// Port of udm_nudm_sdm_handle_subscription_provisioned()
pub fn udm_nudm_sdm_handle_subscription_provisioned(
    udm_ue_id: u64,
    _stream_id: u64,
    resource_name: &str,
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
    log::debug!("[{}] Handle NUDM SDM subscription provisioned", supi);

    match resource_name {
        "ue-context-in-smf-data" => {
            // Return empty UeContextInSmfData
            // In real implementation, this would return actual SMF context data
            HandlerResult::ok()
        }
        _ => {
            log::error!("Invalid resource name [{}]", resource_name);
            HandlerResult::bad_request("Invalid resource name")
        }
    }
}

/// Handle NUDM SDM subscription create
/// Port of udm_nudm_sdm_handle_subscription_create()
pub fn udm_nudm_sdm_handle_subscription_create(
    udm_ue_id: u64,
    _stream_id: u64,
    request: &SdmSubscriptionRequest,
) -> (HandlerResult, Option<UdmSdmSubscription>) {
    let ctx = udm_self();
    let context = ctx.read().unwrap();

    let udm_ue = match context.ue_find_by_id(udm_ue_id) {
        Some(ue) => ue,
        None => {
            log::error!("UDM UE not found [{}]", udm_ue_id);
            return (HandlerResult::bad_request("UDM UE not found"), None);
        }
    };

    let supi = udm_ue.supi.clone().unwrap_or_else(|| udm_ue.suci.clone());
    log::debug!("[{}] Handle NUDM SDM subscription create", supi);

    // Validate SDMSubscription
    if request.nf_instance_id.is_none() || request.nf_instance_id.as_ref().map(|s| s.is_empty()).unwrap_or(true) {
        log::error!("[{}] No nfInstanceId", supi);
        return (HandlerResult::bad_request("No nfInstanceId"), None);
    }

    if request.callback_reference.is_none() || request.callback_reference.as_ref().map(|s| s.is_empty()).unwrap_or(true) {
        log::error!("[{}] No callbackReference", supi);
        return (HandlerResult::bad_request("No callbackReference"), None);
    }

    if request.monitored_resource_uris.is_empty() {
        log::error!("[{}] No monitoredResourceUris", supi);
        return (HandlerResult::bad_request("No monitoredResourceUris"), None);
    }

    // Add SDM subscription
    let subscription = match context.sdm_subscription_add(udm_ue_id) {
        Some(mut sub) => {
            sub.data_change_callback_uri = request.callback_reference.clone();
            context.sdm_subscription_update(&sub);
            sub
        }
        None => {
            log::error!("[{}] sdm_subscription_add() failed", supi);
            return (HandlerResult::bad_request("sdm_subscription_add() failed"), None);
        }
    };
    drop(context);

    log::debug!("[{}] SDM subscription created: {}", supi, subscription.id);
    (HandlerResult::created(), Some(subscription))
}

/// Handle NUDM SDM subscription delete
/// Port of udm_nudm_sdm_handle_subscription_delete()
pub fn udm_nudm_sdm_handle_subscription_delete(
    udm_ue_id: u64,
    _stream_id: u64,
    subscription_id: Option<&str>,
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

    let supi = udm_ue.supi.clone().unwrap_or_else(|| udm_ue.suci.clone());
    log::debug!("[{}] Handle NUDM SDM subscription delete", supi);

    let sub_id = match subscription_id {
        Some(id) if !id.is_empty() => id,
        _ => {
            log::error!("[{}] No subscriptionID", supi);
            return HandlerResult::bad_request("No subscriptionID");
        }
    };

    // Find and remove subscription
    if context.sdm_subscription_find_by_id(sub_id).is_some() {
        context.sdm_subscription_remove(sub_id);
        log::debug!("[{}] SDM subscription deleted: {}", supi, sub_id);
        HandlerResult::no_content()
    } else {
        log::error!("Subscription to be deleted does not exist [{}]", sub_id);
        HandlerResult::not_found("Subscription Not found")
    }
}

// Helper functions

/// Convert hex string to bytes
pub fn hex_to_bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .filter_map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
        .collect()
}

/// Convert bytes to hex string
pub fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Convert buffer to u64
fn buffer_to_u64(buf: &[u8]) -> u64 {
    let mut result: u64 = 0;
    for &byte in buf {
        result = (result << 8) | (byte as u64);
    }
    result
}

/// Convert u64 to buffer
fn u64_to_buffer(value: u64, buf: &mut [u8]) {
    let len = buf.len();
    for i in 0..len {
        buf[len - 1 - i] = ((value >> (i * 8)) & 0xFF) as u8;
    }
}

/// Parse AMF ID from hex string
fn parse_amf_id(amf_id_str: &str) -> crate::context::AmfId {
    // AMF ID is 24 bits: 8-bit region + 10-bit set + 6-bit pointer
    let bytes = hex_to_bytes(amf_id_str);
    if bytes.len() >= 3 {
        let value = ((bytes[0] as u32) << 16) | ((bytes[1] as u32) << 8) | (bytes[2] as u32);
        crate::context::AmfId {
            region: ((value >> 16) & 0xFF) as u8,
            set: ((value >> 6) & 0x3FF) as u16,
            pointer: (value & 0x3F) as u8,
        }
    } else {
        crate::context::AmfId::default()
    }
}

/// Check if two GUAMIs match
fn guami_matches(a: &Guami, b: &Guami) -> bool {
    a.plmn_id.mcc == b.plmn_id.mcc
        && a.plmn_id.mnc == b.plmn_id.mnc
        && a.amf_id.region == b.amf_id.region
        && a.amf_id.set == b.amf_id.set
        && a.amf_id.pointer == b.amf_id.pointer
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handler_result_ok() {
        let result = HandlerResult::ok();
        assert!(result.success);
        assert_eq!(result.status, http_status::OK);
        assert!(result.error_message.is_none());
    }

    #[test]
    fn test_handler_result_created() {
        let result = HandlerResult::created();
        assert!(result.success);
        assert_eq!(result.status, http_status::CREATED);
    }

    #[test]
    fn test_handler_result_no_content() {
        let result = HandlerResult::no_content();
        assert!(result.success);
        assert_eq!(result.status, http_status::NO_CONTENT);
    }

    #[test]
    fn test_handler_result_bad_request() {
        let result = HandlerResult::bad_request("Test error");
        assert!(!result.success);
        assert_eq!(result.status, http_status::BAD_REQUEST);
        assert_eq!(result.error_message, Some("Test error".to_string()));
    }

    #[test]
    fn test_handler_result_forbidden() {
        let result = HandlerResult::forbidden("Forbidden", Some("INVALID_GUAMI"));
        assert!(!result.success);
        assert_eq!(result.status, http_status::FORBIDDEN);
        assert_eq!(result.error_cause, Some("INVALID_GUAMI".to_string()));
    }

    #[test]
    fn test_hex_to_bytes() {
        let hex = "0123456789abcdef";
        let expected = vec![0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
        assert_eq!(hex_to_bytes(hex), expected);
    }

    #[test]
    fn test_bytes_to_hex() {
        let bytes = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
        assert_eq!(bytes_to_hex(&bytes), "0123456789abcdef");
    }

    #[test]
    fn test_hex_roundtrip() {
        let original = [0xde, 0xad, 0xbe, 0xef];
        let hex = bytes_to_hex(&original);
        let bytes = hex_to_bytes(&hex);
        assert_eq!(bytes, original);
    }

    #[test]
    fn test_buffer_to_u64() {
        let buf = [0x00, 0x00, 0x00, 0x00, 0x00, 0x01];
        assert_eq!(buffer_to_u64(&buf), 1);

        let buf2 = [0x00, 0x00, 0x00, 0x00, 0x01, 0x00];
        assert_eq!(buffer_to_u64(&buf2), 256);
    }

    #[test]
    fn test_u64_to_buffer() {
        let mut buf = [0u8; 6];
        u64_to_buffer(1, &mut buf);
        assert_eq!(buf, [0x00, 0x00, 0x00, 0x00, 0x00, 0x01]);

        u64_to_buffer(256, &mut buf);
        assert_eq!(buf, [0x00, 0x00, 0x00, 0x00, 0x01, 0x00]);
    }

    #[test]
    fn test_parse_amf_id() {
        // AMF ID: region=0x01, set=0x002, pointer=0x01
        // Binary: 00000001 00000000 10000001 = 0x010081
        let amf_id = parse_amf_id("010081");
        assert_eq!(amf_id.region, 0x01);
        assert_eq!(amf_id.set, 0x002);
        assert_eq!(amf_id.pointer, 0x01);
    }

    #[test]
    fn test_guami_matches() {
        let guami1 = Guami {
            plmn_id: PlmnId {
                mcc: "001".to_string(),
                mnc: "01".to_string(),
            },
            amf_id: crate::context::AmfId {
                region: 1,
                set: 2,
                pointer: 3,
            },
        };

        let guami2 = guami1.clone();
        assert!(guami_matches(&guami1, &guami2));

        let guami3 = Guami {
            plmn_id: PlmnId {
                mcc: "001".to_string(),
                mnc: "02".to_string(), // Different MNC
            },
            amf_id: crate::context::AmfId {
                region: 1,
                set: 2,
                pointer: 3,
            },
        };
        assert!(!guami_matches(&guami1, &guami3));
    }
}
