//! NPCF Handler Implementation
//!
//! Port of src/pcf/npcf-handler.c - Handlers for NPCF service requests

use crate::context::{pcf_self, AccessType, Ambr, Guami, PcfApp, PcfSess, PcfUeAm, RatType, SNssai};
use crate::sbi_path::{
    pcf_sbi_send_smpolicycontrol_update_notify,
    pcf_ue_am_sbi_discover_and_send,
    pcf_sess_sbi_discover_and_send,
};

/// HTTP Status codes
pub const HTTP_STATUS_OK: u16 = 200;
pub const HTTP_STATUS_CREATED: u16 = 201;
pub const HTTP_STATUS_NO_CONTENT: u16 = 204;
pub const HTTP_STATUS_BAD_REQUEST: u16 = 400;
pub const HTTP_STATUS_FORBIDDEN: u16 = 403;
pub const HTTP_STATUS_NOT_FOUND: u16 = 404;
pub const HTTP_STATUS_INTERNAL_SERVER_ERROR: u16 = 500;

/// Policy Association Request data
#[derive(Debug, Clone, Default)]
pub struct PolicyAssociationRequest {
    pub notification_uri: Option<String>,
    pub supi: Option<String>,
    pub supp_feat: Option<String>,
    pub gpsi: Option<String>,
    pub access_type: AccessType,
    pub pei: Option<String>,
    pub guami: Option<Guami>,
    pub rat_type: RatType,
    pub ue_ambr: Option<Ambr>,
    pub allowed_snssais: Vec<SNssai>,
}


/// SM Policy Context Data
#[derive(Debug, Clone, Default)]
pub struct SmPolicyContextData {
    pub supi: Option<String>,
    pub pdu_session_id: Option<u8>,
    pub pdu_session_type: Option<String>,
    pub dnn: Option<String>,
    pub notification_uri: Option<String>,
    pub ipv4_address: Option<String>,
    pub ipv6_address_prefix: Option<String>,
    pub slice_info: Option<SNssai>,
    pub serving_network: Option<ServingNetwork>,
    pub gpsi: Option<String>,
    pub supp_feat: Option<String>,
    pub subs_sess_ambr: Option<Ambr>,
}

/// Serving Network info
#[derive(Debug, Clone, Default)]
pub struct ServingNetwork {
    pub mcc: String,
    pub mnc: String,
}

/// SM Policy Delete Data
#[derive(Debug, Clone, Default)]
pub struct SmPolicyDeleteData {
    pub user_location_info: Option<String>,
}

/// App Session Context Request Data
#[derive(Debug, Clone, Default)]
pub struct AscReqData {
    pub supp_feat: Option<String>,
    pub notif_uri: Option<String>,
    pub med_components: Vec<MediaComponent>,
}

/// Media Component
#[derive(Debug, Clone, Default)]
pub struct MediaComponent {
    pub med_comp_n: u32,
    pub med_type: MediaType,
    pub mar_bw_dl: Option<String>,
    pub mar_bw_ul: Option<String>,
    pub mir_bw_dl: Option<String>,
    pub mir_bw_ul: Option<String>,
    pub rr_bw: Option<String>,
    pub rs_bw: Option<String>,
    pub f_status: FlowStatus,
    pub med_sub_comps: Vec<MediaSubComponent>,
}

/// Media Type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MediaType {
    #[default]
    Audio,
    Video,
    Control,
    Application,
    Message,
    Other,
}

/// Flow Status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FlowStatus {
    #[default]
    Enabled,
    Disabled,
    EnabledUplink,
    EnabledDownlink,
    Removed,
}

/// Media Sub Component
#[derive(Debug, Clone, Default)]
pub struct MediaSubComponent {
    pub f_num: u32,
    pub flow_usage: FlowUsage,
    pub f_descs: Vec<String>,
}

/// Flow Usage
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FlowUsage {
    #[default]
    NoInfo,
    Rtcp,
    Af,
}


/// Handler result
#[derive(Debug)]
pub struct HandlerResult {
    pub success: bool,
    pub status: u16,
    pub error_message: Option<String>,
}

impl HandlerResult {
    pub fn ok() -> Self {
        Self {
            success: true,
            status: HTTP_STATUS_OK,
            error_message: None,
        }
    }

    pub fn created() -> Self {
        Self {
            success: true,
            status: HTTP_STATUS_CREATED,
            error_message: None,
        }
    }

    pub fn no_content() -> Self {
        Self {
            success: true,
            status: HTTP_STATUS_NO_CONTENT,
            error_message: None,
        }
    }

    pub fn error(status: u16, message: &str) -> Self {
        Self {
            success: false,
            status,
            error_message: Some(message.to_string()),
        }
    }
}

/// Handle AM Policy Control Create request
/// Port of pcf_npcf_am_policy_control_handle_create() from npcf-handler.c
pub fn pcf_npcf_am_policy_control_handle_create(
    pcf_ue_am: &mut PcfUeAm,
    stream_id: u64,
    request: &PolicyAssociationRequest,
) -> HandlerResult {
    log::debug!(
        "[{}] AM Policy Control Create",
        pcf_ue_am.supi
    );

    // Validate required fields
    if request.notification_uri.is_none() {
        log::error!("[{}] No notificationUri", pcf_ue_am.supi);
        return HandlerResult::error(HTTP_STATUS_BAD_REQUEST, "No notificationUri");
    }

    if request.supi.is_none() {
        log::error!("[{}] No supi", pcf_ue_am.supi);
        return HandlerResult::error(HTTP_STATUS_BAD_REQUEST, "No supi");
    }

    if request.supp_feat.is_none() {
        log::error!("[{}] No suppFeat", pcf_ue_am.supi);
        return HandlerResult::error(HTTP_STATUS_BAD_REQUEST, "No suppFeat");
    }


    // Store notification URI
    pcf_ue_am.notification_uri = request.notification_uri.clone();

    // Parse supported features
    if let Some(ref supp_feat) = request.supp_feat {
        if let Ok(features) = u64::from_str_radix(supp_feat, 16) {
            pcf_ue_am.am_policy_control_features &= features;
        }
    }

    // Store optional fields
    if let Some(ref gpsi) = request.gpsi {
        pcf_ue_am.gpsi = Some(gpsi.clone());
    }

    pcf_ue_am.access_type = request.access_type;

    if let Some(ref pei) = request.pei {
        pcf_ue_am.pei = Some(pei.clone());
    }

    if let Some(ref guami) = request.guami {
        pcf_ue_am.guami = guami.clone();
    }

    pcf_ue_am.rat_type = request.rat_type;

    if let Some(ref ue_ambr) = request.ue_ambr {
        pcf_ue_am.subscribed_ue_ambr = Some(ue_ambr.clone());
    }

    // Check if SUPI is in VPLMN (visited PLMN)
    let is_vplmn = is_supi_in_vplmn(&pcf_ue_am.supi);

    if is_vplmn {
        // Visited PLMN - return immediately with PolicyAssociation
        log::debug!("[{}] VPLMN - returning PolicyAssociation", pcf_ue_am.supi);
        HandlerResult::created()
    } else {
        // Home PLMN - query UDR for AM data
        log::debug!("[{}] HPLMN - querying UDR for AM data", pcf_ue_am.supi);
        if let Err(e) = pcf_ue_am_sbi_discover_and_send(pcf_ue_am.id, stream_id, "nudr-dr") {
            log::error!("[{}] Failed to discover UDR: {}", pcf_ue_am.supi, e);
            return HandlerResult::error(HTTP_STATUS_INTERNAL_SERVER_ERROR, "Failed to discover UDR");
        }
        HandlerResult::ok()
    }
}

/// Handle AM Policy Control Delete request
pub fn pcf_npcf_am_policy_control_handle_delete(
    pcf_ue_am: &PcfUeAm,
    _stream_id: u64,
) -> HandlerResult {
    log::debug!(
        "[{}] AM Policy Control Delete",
        pcf_ue_am.supi
    );

    // In C: Just send NO_CONTENT response
    // The actual cleanup is done by the state machine
    HandlerResult::no_content()
}


/// Handle SM Policy Control Create request
/// Port of pcf_npcf_smpolicycontrol_handle_create() from npcf-handler.c
pub fn pcf_npcf_smpolicycontrol_handle_create(
    sess: &mut PcfSess,
    pcf_ue_sm_supi: &str,
    stream_id: u64,
    request: &SmPolicyContextData,
) -> HandlerResult {
    log::debug!(
        "[{}:{}] SM Policy Control Create",
        pcf_ue_sm_supi,
        sess.psi
    );

    // Validate required fields
    if request.supi.is_none() {
        return HandlerResult::error(
            HTTP_STATUS_BAD_REQUEST,
            &format!("[{}:{}] No supi", pcf_ue_sm_supi, sess.psi),
        );
    }

    if request.pdu_session_id.is_none() {
        return HandlerResult::error(
            HTTP_STATUS_BAD_REQUEST,
            &format!("[{}:{}] No pduSessionId", pcf_ue_sm_supi, sess.psi),
        );
    }

    if request.pdu_session_type.is_none() {
        return HandlerResult::error(
            HTTP_STATUS_BAD_REQUEST,
            &format!("[{}:{}] No pduSessionType", pcf_ue_sm_supi, sess.psi),
        );
    }

    if request.dnn.is_none() {
        return HandlerResult::error(
            HTTP_STATUS_BAD_REQUEST,
            &format!("[{}:{}] No dnn", pcf_ue_sm_supi, sess.psi),
        );
    }

    if request.notification_uri.is_none() {
        return HandlerResult::error(
            HTTP_STATUS_BAD_REQUEST,
            &format!("[{}:{}] No notificationUri", pcf_ue_sm_supi, sess.psi),
        );
    }

    if request.ipv4_address.is_none() && request.ipv6_address_prefix.is_none() {
        return HandlerResult::error(
            HTTP_STATUS_BAD_REQUEST,
            &format!("[{}:{}] No IPv4 address or IPv6 prefix", pcf_ue_sm_supi, sess.psi),
        );
    }

    if request.slice_info.is_none() {
        return HandlerResult::error(
            HTTP_STATUS_BAD_REQUEST,
            &format!("[{}:{}] No sliceInfo", pcf_ue_sm_supi, sess.psi),
        );
    }


    // Parse supported features
    if let Some(ref supp_feat) = request.supp_feat {
        if let Ok(features) = u64::from_str_radix(supp_feat, 16) {
            sess.smpolicycontrol_features &= features;
        }
    } else {
        sess.smpolicycontrol_features = 0;
    }

    // Store DNN
    if let Some(ref dnn) = request.dnn {
        // Parse DNN - may contain operator identifier
        if let Some(oi_pos) = dnn.find(".mnc") {
            sess.dnn = Some(dnn[..oi_pos].to_string());
            sess.full_dnn = Some(dnn.clone());
        } else {
            sess.dnn = Some(dnn.clone());
            sess.full_dnn = None;
        }
    }

    // Store notification URI
    sess.notification_uri = request.notification_uri.clone();

    // Store IP addresses
    if let Some(ref ipv4) = request.ipv4_address {
        sess.set_ipv4addr(ipv4);
    }
    if let Some(ref ipv6) = request.ipv6_address_prefix {
        sess.set_ipv6prefix(ipv6);
    }

    // Store S-NSSAI
    if let Some(ref slice_info) = request.slice_info {
        sess.s_nssai = slice_info.clone();
    }

    // Store serving network
    if let Some(ref serving) = request.serving_network {
        sess.serving.presence = true;
        sess.serving.plmn_id.mcc = serving.mcc.clone();
        sess.serving.plmn_id.mnc = serving.mnc.clone();
        sess.home.presence = true;
        sess.home.plmn_id = sess.serving.plmn_id.clone();
    }

    // Store subscribed session AMBR
    if let Some(ref ambr) = request.subs_sess_ambr {
        sess.subscribed_sess_ambr = Some(ambr.clone());
    }

    // Check if SUPI is in VPLMN
    let is_vplmn = is_supi_in_vplmn(pcf_ue_sm_supi);

    if is_vplmn {
        // Visited PLMN - register with BSF
        log::debug!("[{}:{}] VPLMN - registering with BSF", pcf_ue_sm_supi, sess.psi);
        if let Err(e) = pcf_sess_sbi_discover_and_send(sess.id, stream_id, "nbsf-management") {
            log::error!("[{}:{}] Failed to discover BSF: {}", pcf_ue_sm_supi, sess.psi, e);
            return HandlerResult::error(HTTP_STATUS_INTERNAL_SERVER_ERROR, "Failed to discover BSF");
        }
    } else {
        // Home PLMN - query UDR for SM data
        log::debug!("[{}:{}] HPLMN - querying UDR for SM data", pcf_ue_sm_supi, sess.psi);
        if let Err(e) = pcf_sess_sbi_discover_and_send(sess.id, stream_id, "nudr-dr") {
            log::error!("[{}:{}] Failed to discover UDR: {}", pcf_ue_sm_supi, sess.psi, e);
            return HandlerResult::error(HTTP_STATUS_INTERNAL_SERVER_ERROR, "Failed to discover UDR");
        }
    }

    HandlerResult::ok()
}


/// Handle SM Policy Control Delete request
/// Port of pcf_npcf_smpolicycontrol_handle_delete() from npcf-handler.c
pub fn pcf_npcf_smpolicycontrol_handle_delete(
    sess: &PcfSess,
    pcf_ue_sm_supi: &str,
    stream_id: u64,
    _request: &SmPolicyDeleteData,
) -> HandlerResult {
    log::debug!(
        "[{}:{}] SM Policy Control Delete",
        pcf_ue_sm_supi,
        sess.psi
    );

    let ctx = pcf_self();
    let context = match ctx.read() {
        Ok(c) => c,
        Err(_) => return HandlerResult::error(HTTP_STATUS_INTERNAL_SERVER_ERROR, "Context lock failed"),
    };

    // Send terminate notify to all app sessions
    for app_id in &sess.app_ids {
        if let Some(_app) = context.app_find_by_id(*app_id) {
            crate::sbi_path::pcf_sbi_send_policyauthorization_terminate_notify(*app_id);
        }
    }

    // Check if this is the last session with same S-NSSAI and DNN
    let sessions_count = if let Some(ref dnn) = sess.dnn {
        context.sessions_number_by_snssai_and_dnn(sess.pcf_ue_sm_id, &sess.s_nssai, dnn)
    } else {
        0
    };

    if sessions_count > 1 {
        // Not the last session - just return NO_CONTENT
        HandlerResult::no_content()
    } else if sess.binding.is_associated() {
        // Last session with BSF binding - deregister from BSF
        log::debug!("[{}:{}] Deregistering from BSF", pcf_ue_sm_supi, sess.psi);
        if let Err(e) = pcf_sess_sbi_discover_and_send(sess.id, stream_id, "nbsf-management") {
            log::error!("[{}:{}] Failed to discover BSF: {}", pcf_ue_sm_supi, sess.psi, e);
        }
        HandlerResult::ok()
    } else {
        HandlerResult::no_content()
    }
}

/// Handle Policy Authorization Create request
/// Port of pcf_npcf_policyauthorization_handle_create() from npcf-handler.c
pub fn pcf_npcf_policyauthorization_handle_create(
    sess: &mut PcfSess,
    pcf_ue_sm_supi: &str,
    _stream_id: u64,
    request: &AscReqData,
) -> HandlerResult {
    log::debug!(
        "[{}:{}] Policy Authorization Create",
        pcf_ue_sm_supi,
        sess.psi
    );

    // Validate required fields
    if request.supp_feat.is_none() {
        return HandlerResult::error(
            HTTP_STATUS_BAD_REQUEST,
            &format!("[{}:{}] No suppFeat", pcf_ue_sm_supi, sess.psi),
        );
    }

    if request.notif_uri.is_none() {
        return HandlerResult::error(
            HTTP_STATUS_BAD_REQUEST,
            &format!("[{}:{}] No notifUri", pcf_ue_sm_supi, sess.psi),
        );
    }

    if request.med_components.is_empty() {
        return HandlerResult::error(
            HTTP_STATUS_BAD_REQUEST,
            &format!("[{}:{}] No MediaComponent", pcf_ue_sm_supi, sess.psi),
        );
    }


    // Parse supported features
    if let Some(ref supp_feat) = request.supp_feat {
        if let Ok(features) = u64::from_str_radix(supp_feat, 16) {
            sess.policyauthorization_features &= features;
        }
    }

    // Create app session
    let ctx = pcf_self();
    let context = match ctx.read() {
        Ok(c) => c,
        Err(_) => return HandlerResult::error(HTTP_STATUS_INTERNAL_SERVER_ERROR, "Context lock failed"),
    };

    let app_session = match context.app_add(sess.id) {
        Some(app) => app,
        None => {
            return HandlerResult::error(
                HTTP_STATUS_INTERNAL_SERVER_ERROR,
                &format!("[{}:{}] Failed to create app session", pcf_ue_sm_supi, sess.psi),
            );
        }
    };

    // Store notification URI in app session
    let mut app = app_session.clone();
    app.notif_uri = request.notif_uri.clone();
    context.app_update(&app);

    // Process media components and build PCC rules
    // In C: This involves complex IMS data processing
    // For now, just log and return success
    for (i, mc) in request.med_components.iter().enumerate() {
        log::debug!(
            "[{}:{}] MediaComponent[{}]: type={:?}, status={:?}",
            pcf_ue_sm_supi,
            sess.psi,
            i,
            mc.med_type,
            mc.f_status
        );
    }

    // Send SM policy control update notify if PCC rules were created
    let _ = pcf_sbi_send_smpolicycontrol_update_notify(sess.id);

    HandlerResult::created()
}

/// Handle Policy Authorization Update request
/// Port of pcf_npcf_policyauthorization_handle_update() from npcf-handler.c
pub fn pcf_npcf_policyauthorization_handle_update(
    sess: &PcfSess,
    app: &PcfApp,
    pcf_ue_sm_supi: &str,
    _stream_id: u64,
    request: &AscReqData,
) -> HandlerResult {
    log::debug!(
        "[{}:{}] Policy Authorization Update (app={})",
        pcf_ue_sm_supi,
        sess.psi,
        app.app_session_id
    );

    // Validate media components
    if request.med_components.is_empty() {
        return HandlerResult::error(
            HTTP_STATUS_BAD_REQUEST,
            &format!("[{}:{}] No MediaComponent", pcf_ue_sm_supi, sess.psi),
        );
    }

    // Process media components and update PCC rules
    // In C: This involves complex IMS data processing
    for (i, mc) in request.med_components.iter().enumerate() {
        log::debug!(
            "[{}:{}] MediaComponent[{}]: type={:?}, status={:?}",
            pcf_ue_sm_supi,
            sess.psi,
            i,
            mc.med_type,
            mc.f_status
        );
    }

    // Send SM policy control update notify if PCC rules were updated
    let _ = pcf_sbi_send_smpolicycontrol_update_notify(sess.id);

    HandlerResult::ok()
}


/// Handle Policy Authorization Delete request
/// Port of pcf_npcf_policyauthorization_handle_delete() from npcf-handler.c
pub fn pcf_npcf_policyauthorization_handle_delete(
    sess: &PcfSess,
    app: &PcfApp,
    pcf_ue_sm_supi: &str,
    _stream_id: u64,
) -> HandlerResult {
    log::debug!(
        "[{}:{}] Policy Authorization Delete (app={})",
        pcf_ue_sm_supi,
        sess.psi,
        app.app_session_id
    );

    // In C: Build SmPolicyDecision with PCC rules to delete
    // and send smpolicycontrol_delete_notify

    // Send delete notify (which will remove app session after callback)
    crate::sbi_path::pcf_sbi_send_smpolicycontrol_delete_notify(sess.id, app.id);

    HandlerResult::no_content()
}

/// Check if SUPI is in visited PLMN
/// Port of ogs_sbi_supi_in_vplmn() from lib/sbi/
fn is_supi_in_vplmn(supi: &str) -> bool {
    // In C: This checks if the SUPI's PLMN ID matches the local PLMN ID
    // Note: Proper VPLMN detection requires configuration of local PLMN ID
    // For now, return false (assume home PLMN)
    log::trace!("Checking if SUPI {supi} is in VPLMN");
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handler_result_ok() {
        let result = HandlerResult::ok();
        assert!(result.success);
        assert_eq!(result.status, HTTP_STATUS_OK);
        assert!(result.error_message.is_none());
    }

    #[test]
    fn test_handler_result_created() {
        let result = HandlerResult::created();
        assert!(result.success);
        assert_eq!(result.status, HTTP_STATUS_CREATED);
    }

    #[test]
    fn test_handler_result_no_content() {
        let result = HandlerResult::no_content();
        assert!(result.success);
        assert_eq!(result.status, HTTP_STATUS_NO_CONTENT);
    }

    #[test]
    fn test_handler_result_error() {
        let result = HandlerResult::error(HTTP_STATUS_BAD_REQUEST, "Test error");
        assert!(!result.success);
        assert_eq!(result.status, HTTP_STATUS_BAD_REQUEST);
        assert_eq!(result.error_message, Some("Test error".to_string()));
    }

    #[test]
    fn test_policy_association_request_default() {
        let req = PolicyAssociationRequest::default();
        assert!(req.notification_uri.is_none());
        assert!(req.supi.is_none());
        assert!(req.supp_feat.is_none());
    }

    #[test]
    fn test_sm_policy_context_data_default() {
        let req = SmPolicyContextData::default();
        assert!(req.supi.is_none());
        assert!(req.pdu_session_id.is_none());
        assert!(req.dnn.is_none());
    }

    #[test]
    fn test_media_type_default() {
        let mt = MediaType::default();
        assert_eq!(mt, MediaType::Audio);
    }

    #[test]
    fn test_flow_status_default() {
        let fs = FlowStatus::default();
        assert_eq!(fs, FlowStatus::Enabled);
    }
}
