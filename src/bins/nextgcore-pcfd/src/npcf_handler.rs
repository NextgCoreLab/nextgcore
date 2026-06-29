//! NPCF Handler Implementation
//!
//! Port of src/pcf/npcf-handler.c - Handlers for NPCF service requests

use crate::context::{
    pcf_self, AccessType, Ambr, Guami, PcfApp, PcfSess, PcfUeAm, RatType, SNssai,
};
use crate::sbi_path::{
    pcf_sbi_send_smpolicycontrol_update_notify, pcf_sess_sbi_discover_and_send,
    pcf_ue_am_sbi_discover_and_send,
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
    /// Reference to a pre-provisioned QoS (TS 29.514 `qosReference`). When it
    /// parses to a numeric 5QI it overrides the media-type default 5QI.
    pub qos_ref: Option<String>,
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

impl MediaType {
    /// Parse the TS 29.514 `medType` enum string.
    pub fn from_wire(s: &str) -> Self {
        match s {
            "AUDIO" => MediaType::Audio,
            "VIDEO" => MediaType::Video,
            "CONTROL" => MediaType::Control,
            "APPLICATION" => MediaType::Application,
            "MESSAGE" => MediaType::Message,
            _ => MediaType::Other,
        }
    }

    /// Default 5QI applied by operator policy when the media component does not
    /// carry a numeric `qosReference` (TS 23.501 Table 5.7.4-1 standardised
    /// 5QIs): conversational voice/video are GBR, everything else maps to the
    /// non-GBR default bearer 5QI 9.
    pub fn default_5qi(self) -> u8 {
        match self {
            MediaType::Audio => 1,       // conversational voice (GBR)
            MediaType::Video => 2,       // conversational video / live (GBR)
            MediaType::Control => 5,     // IMS signalling (non-GBR)
            MediaType::Application | MediaType::Message | MediaType::Other => 9,
        }
    }
}

/// Whether a standardised 5QI denotes a GBR / delay-critical-GBR resource type
/// (TS 23.501 Table 5.7.4-1). GBR rules carry a `gbr{Ul,Dl}` alongside `maxbr`.
pub fn is_gbr_5qi(qi: u8) -> bool {
    matches!(qi, 1..=4 | 65..=67 | 71..=76 | 82..=85)
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

impl FlowStatus {
    /// Parse the TS 29.514 `fStatus` enum string.
    pub fn from_wire(s: &str) -> Self {
        match s {
            "DISABLED" => FlowStatus::Disabled,
            "ENABLED_UPLINK" => FlowStatus::EnabledUplink,
            "ENABLED_DOWNLINK" => FlowStatus::EnabledDownlink,
            "REMOVED" => FlowStatus::Removed,
            _ => FlowStatus::Enabled,
        }
    }

    /// TS 29.512 §5.6.2.10 `flowStatus` wire enum used in traffic-control data.
    pub fn as_wire(self) -> &'static str {
        match self {
            FlowStatus::Enabled => "ENABLED",
            FlowStatus::Disabled => "DISABLED",
            FlowStatus::EnabledUplink => "ENABLED_UPLINK",
            FlowStatus::EnabledDownlink => "ENABLED_DOWNLINK",
            FlowStatus::Removed => "REMOVED",
        }
    }
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

// ---------------------------------------------------------------------------
// AF media component → PCC rule mapping (TS 29.514 §4.2.2.2 → TS 29.512 §5.6.2)
// ---------------------------------------------------------------------------

/// A single flow-information entry inside a PCC rule
/// (TS 29.512 §5.6.2.9 FlowInformation).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowInfo {
    /// IPFilterRule packet filter (TS 29.514 flowDescription).
    pub flow_description: String,
    /// "UPLINK" | "DOWNLINK" | "BIDIRECTIONAL".
    pub flow_direction: String,
    /// Packet filter identifier (unique within the rule).
    pub pack_filt_id: String,
}

/// QoS decision derived from an AF media component
/// (TS 29.512 §5.6.2.8 QosData). Always emits the mandatory `qosId` (pcfd-01).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QosData {
    pub qos_id: String,
    pub five_qi: u8,
    pub maxbr_ul: Option<String>,
    pub maxbr_dl: Option<String>,
    pub gbr_ul: Option<String>,
    pub gbr_dl: Option<String>,
}

impl QosData {
    /// Serialise to the TS 29.512 QosData JSON object. `qosId` is mandatory
    /// (Table 5.6.2.8-1) and equals the qosDecs map key.
    pub fn to_json(&self) -> serde_json::Value {
        let mut obj = serde_json::Map::new();
        obj.insert(
            "qosId".to_string(),
            serde_json::Value::String(self.qos_id.clone()),
        );
        obj.insert("5qi".to_string(), serde_json::json!(self.five_qi));
        if let Some(ref v) = self.maxbr_ul {
            obj.insert("maxbrUl".to_string(), serde_json::Value::String(v.clone()));
        }
        if let Some(ref v) = self.maxbr_dl {
            obj.insert("maxbrDl".to_string(), serde_json::Value::String(v.clone()));
        }
        if let Some(ref v) = self.gbr_ul {
            obj.insert("gbrUl".to_string(), serde_json::Value::String(v.clone()));
        }
        if let Some(ref v) = self.gbr_dl {
            obj.insert("gbrDl".to_string(), serde_json::Value::String(v.clone()));
        }
        serde_json::Value::Object(obj)
    }
}

/// A PCC rule installed at the SMF for an AF media component
/// (TS 29.512 §5.6.2.6 PccRule). Carries flow filters, a QoS reference and the
/// AF-requested flow status. Named `AfPccRule` to distinguish it from the
/// subscription-sourced `nudr_handler::PccRule`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AfPccRule {
    pub pcc_rule_id: String,
    pub precedence: u32,
    pub flow_infos: Vec<FlowInfo>,
    pub qos_data: QosData,
    pub flow_status: FlowStatus,
}

impl AfPccRule {
    /// Serialise to the TS 29.512 PccRule JSON object. `refQosData` points at
    /// the companion QosData (keyed by its `qosId`).
    pub fn to_json(&self) -> serde_json::Value {
        let flows: Vec<serde_json::Value> = self
            .flow_infos
            .iter()
            .map(|f| {
                serde_json::json!({
                    "flowDescription": f.flow_description,
                    "flowDirection": f.flow_direction,
                    "packFiltId": f.pack_filt_id,
                })
            })
            .collect();
        serde_json::json!({
            "pccRuleId": self.pcc_rule_id,
            "precedence": self.precedence,
            "flowInfos": flows,
            "refQosData": [self.qos_data.qos_id.clone()],
            "flowStatus": self.flow_status.as_wire(),
        })
    }
}

/// Map an IPFilterRule action to a PCC `flowDirection` (TS 29.512). "permit
/// out" is network→UE (downlink); "permit in" is UE→network (uplink).
fn flow_direction_from_desc(desc: &str) -> &'static str {
    if desc.contains("permit out") {
        "DOWNLINK"
    } else if desc.contains("permit in") {
        "UPLINK"
    } else {
        "BIDIRECTIONAL"
    }
}

/// Resolve the 5QI for a media component: a numeric `qosReference` wins,
/// otherwise the media-type operator-policy default (TS 23.501 Table 5.7.4-1).
fn five_qi_for_component(mc: &MediaComponent) -> u8 {
    mc.qos_ref
        .as_deref()
        .and_then(|s| s.trim().parse::<u8>().ok())
        .unwrap_or_else(|| mc.med_type.default_5qi())
}

/// Convert AF media components to PCC rules (TS 29.514 §4.2.2.2). For each
/// component the flowDescriptions become flowInfos, `medType`/`marBw{Ul,Dl}`
/// and the resolved 5QI become a QosData (with `gbr` for GBR 5QIs), and
/// `fStatus` becomes the rule flow status. PCC rule ids are stable per
/// (session, medCompN) so a modify replaces the same rule.
pub fn media_components_to_pcc(req: &AscReqData, sess: &PcfSess) -> Vec<AfPccRule> {
    let mut rules = Vec::with_capacity(req.med_components.len());

    for mc in &req.med_components {
        let rule_key = format!("af-{}-{}", sess.psi, mc.med_comp_n);
        let pcc_rule_id = format!("PccRule-{rule_key}");
        let qos_id = format!("QosData-{rule_key}");

        // flowDescriptions from every media sub-component → flowInfos.
        let mut flow_infos = Vec::new();
        for (sc_idx, sc) in mc.med_sub_comps.iter().enumerate() {
            for (fd_idx, fd) in sc.f_descs.iter().enumerate() {
                flow_infos.push(FlowInfo {
                    flow_description: fd.clone(),
                    flow_direction: flow_direction_from_desc(fd).to_string(),
                    pack_filt_id: format!("pf-{rule_key}-{sc_idx}-{fd_idx}"),
                });
            }
        }

        let five_qi = five_qi_for_component(mc);
        let gbr = is_gbr_5qi(five_qi);
        let qos_data = QosData {
            qos_id,
            five_qi,
            maxbr_ul: mc.mar_bw_ul.clone(),
            maxbr_dl: mc.mar_bw_dl.clone(),
            // GBR resources carry a guaranteed bit rate; use the AF maximum
            // requested bandwidth as the guarantee when no separate min is given.
            gbr_ul: if gbr {
                mc.mir_bw_ul.clone().or_else(|| mc.mar_bw_ul.clone())
            } else {
                None
            },
            gbr_dl: if gbr {
                mc.mir_bw_dl.clone().or_else(|| mc.mar_bw_dl.clone())
            } else {
                None
            },
        };

        rules.push(AfPccRule {
            pcc_rule_id,
            // AF-installed dynamic rules take precedence over the default
            // match-all rule (precedence 255).
            precedence: 100 + mc.med_comp_n,
            flow_infos,
            qos_data,
            flow_status: mc.f_status,
        });
    }

    rules
}

/// Assemble the (`pccRules`, `qosDecs`) decision maps from a set of AF PCC
/// rules (TS 29.512 §5.6.2.4 SmPolicyDecision fragments).
pub fn af_pcc_rules_to_decision(rules: &[AfPccRule]) -> (serde_json::Value, serde_json::Value) {
    let mut pcc_map = serde_json::Map::new();
    let mut qos_map = serde_json::Map::new();
    for rule in rules {
        pcc_map.insert(rule.pcc_rule_id.clone(), rule.to_json());
        qos_map.insert(rule.qos_data.qos_id.clone(), rule.qos_data.to_json());
    }
    (
        serde_json::Value::Object(pcc_map),
        serde_json::Value::Object(qos_map),
    )
}

/// Build the SmPolicyNotification body that pushes the AF-derived PCC rules
/// stored on a session to the SMF (TS 29.512 §4.2.3.2). Used by the outbound
/// `pcf_sbi_send_af_smpolicycontrol_update_notify` path.
pub fn build_af_sm_policy_notification(sess: &PcfSess) -> serde_json::Value {
    let (pcc_rules, qos_decs) = af_pcc_rules_to_decision(&sess.af_pcc_rules);
    serde_json::json!({
        "resourceUri": format!("/npcf-smpolicycontrol/v1/sm-policies/{}", sess.sm_policy_id),
        "smPolicyDecision": {
            "pccRules": pcc_rules,
            "qosDecs": qos_decs,
        },
    })
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
    log::debug!("[{}] AM Policy Control Create", pcf_ue_am.supi);

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

    // Determine V-PCF/H-PCF role from the serving PLMN (the AMF GUAMI PLMN for
    // an AM policy association) vs. the configured local PLMN (pcfd-10).
    let is_vplmn =
        is_serving_plmn_vplmn(&pcf_ue_am.guami.plmn_id.mcc, &pcf_ue_am.guami.plmn_id.mnc);

    if is_vplmn {
        // Visited PLMN - return immediately with PolicyAssociation
        log::debug!("[{}] VPLMN - returning PolicyAssociation", pcf_ue_am.supi);
        HandlerResult::created()
    } else {
        // Home PLMN - query UDR for AM data
        log::debug!("[{}] HPLMN - querying UDR for AM data", pcf_ue_am.supi);
        if let Err(e) = pcf_ue_am_sbi_discover_and_send(pcf_ue_am.id, stream_id, "nudr-dr") {
            log::error!("[{}] Failed to discover UDR: {}", pcf_ue_am.supi, e);
            return HandlerResult::error(
                HTTP_STATUS_INTERNAL_SERVER_ERROR,
                "Failed to discover UDR",
            );
        }
        HandlerResult::ok()
    }
}

/// Handle AM Policy Control Delete request
pub fn pcf_npcf_am_policy_control_handle_delete(
    pcf_ue_am: &PcfUeAm,
    _stream_id: u64,
) -> HandlerResult {
    log::debug!("[{}] AM Policy Control Delete", pcf_ue_am.supi);

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
    log::debug!("[{}:{}] SM Policy Control Create", pcf_ue_sm_supi, sess.psi);

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
            &format!(
                "[{}:{}] No IPv4 address or IPv6 prefix",
                pcf_ue_sm_supi, sess.psi
            ),
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

    // Determine V-PCF/H-PCF role from the session's serving PLMN vs. the
    // configured local PLMN (pcfd-10).
    let is_vplmn =
        is_serving_plmn_vplmn(&sess.serving.plmn_id.mcc, &sess.serving.plmn_id.mnc);

    if is_vplmn {
        // Visited PLMN - register with BSF
        log::debug!(
            "[{}:{}] VPLMN - registering with BSF",
            pcf_ue_sm_supi,
            sess.psi
        );
        if let Err(e) = pcf_sess_sbi_discover_and_send(sess.id, stream_id, "nbsf-management") {
            log::error!(
                "[{}:{}] Failed to discover BSF: {}",
                pcf_ue_sm_supi,
                sess.psi,
                e
            );
            return HandlerResult::error(
                HTTP_STATUS_INTERNAL_SERVER_ERROR,
                "Failed to discover BSF",
            );
        }
    } else {
        // Home PLMN - query UDR for SM data
        log::debug!(
            "[{}:{}] HPLMN - querying UDR for SM data",
            pcf_ue_sm_supi,
            sess.psi
        );
        if let Err(e) = pcf_sess_sbi_discover_and_send(sess.id, stream_id, "nudr-dr") {
            log::error!(
                "[{}:{}] Failed to discover UDR: {}",
                pcf_ue_sm_supi,
                sess.psi,
                e
            );
            return HandlerResult::error(
                HTTP_STATUS_INTERNAL_SERVER_ERROR,
                "Failed to discover UDR",
            );
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
    log::debug!("[{}:{}] SM Policy Control Delete", pcf_ue_sm_supi, sess.psi);

    let ctx = pcf_self();
    let context = match ctx.read() {
        Ok(c) => c,
        Err(_) => {
            return HandlerResult::error(HTTP_STATUS_INTERNAL_SERVER_ERROR, "Context lock failed")
        }
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
            log::error!(
                "[{}:{}] Failed to discover BSF: {}",
                pcf_ue_sm_supi,
                sess.psi,
                e
            );
        }
        HandlerResult::ok()
    } else {
        HandlerResult::no_content()
    }
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

/// Configured local (home) PLMN as `(mcc, mnc)`, read from the `PCF_LOCAL_PLMN`
/// environment variable formatted "MCC-MNC" (e.g. "001-01"); defaults to
/// 001/01 when unset or malformed.
fn local_plmn() -> (String, String) {
    let raw = std::env::var("PCF_LOCAL_PLMN").unwrap_or_else(|_| "001-01".to_string());
    match raw.split_once('-') {
        Some((mcc, mnc)) => (mcc.trim().to_string(), mnc.trim().to_string()),
        None => ("001".to_string(), "01".to_string()),
    }
}

/// Whether a request's serving PLMN identifies a visited PLMN (V-PCF role).
///
/// Drives the V-PCF / H-PCF BSF behavior from the serving network rather than a
/// hardcoded `false` (pcfd-10): true when the serving PLMN differs from the
/// configured local PLMN. An empty/absent serving PLMN is treated as home
/// (`false`), preserving the H-PCF default for non-roaming sessions.
pub fn is_serving_plmn_vplmn(serving_mcc: &str, serving_mnc: &str) -> bool {
    if serving_mcc.is_empty() && serving_mnc.is_empty() {
        return false;
    }
    let (local_mcc, local_mnc) = local_plmn();
    serving_mcc != local_mcc || serving_mnc != local_mnc
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

    /// pcfd-02: TS 29.514 §4.2.2.2 — an AscReqData with one audio media
    /// component (flowDescriptions + marBwDl/Ul) maps to a PccRule with matching
    /// flowInfos and a QosData carrying the right maxbr and the mandatory qosId.
    #[test]
    fn test_media_components_to_pcc_audio_component() {
        let sess = PcfSess::new(1, 1, 5);
        let req = AscReqData {
            supp_feat: Some("0".to_string()),
            notif_uri: Some("http://af/notif".to_string()),
            med_components: vec![MediaComponent {
                med_comp_n: 1,
                med_type: MediaType::Audio,
                mar_bw_dl: Some("256 Kbps".to_string()),
                mar_bw_ul: Some("128 Kbps".to_string()),
                f_status: FlowStatus::Enabled,
                med_sub_comps: vec![MediaSubComponent {
                    f_num: 1,
                    flow_usage: FlowUsage::NoInfo,
                    f_descs: vec![
                        "permit out ip from 10.45.0.77 to any".to_string(),
                        "permit in ip from any to 10.45.0.77".to_string(),
                    ],
                }],
                ..Default::default()
            }],
        };

        let rules = media_components_to_pcc(&req, &sess);
        assert_eq!(rules.len(), 1);
        let rule = &rules[0];
        assert_eq!(rule.pcc_rule_id, "PccRule-af-5-1");
        assert_eq!(rule.precedence, 101);
        assert_eq!(rule.flow_status, FlowStatus::Enabled);

        // flowInfos mirror the media sub-component flow descriptions/directions.
        assert_eq!(rule.flow_infos.len(), 2);
        assert_eq!(
            rule.flow_infos[0].flow_description,
            "permit out ip from 10.45.0.77 to any"
        );
        assert_eq!(rule.flow_infos[0].flow_direction, "DOWNLINK");
        assert_eq!(rule.flow_infos[1].flow_direction, "UPLINK");

        // QosData: audio → GBR 5QI 1 with the AF-requested maxbr and a qosId.
        let qos = &rule.qos_data;
        assert_eq!(qos.five_qi, 1);
        assert_eq!(qos.maxbr_dl.as_deref(), Some("256 Kbps"));
        assert_eq!(qos.maxbr_ul.as_deref(), Some("128 Kbps"));
        assert_eq!(qos.gbr_dl.as_deref(), Some("256 Kbps")); // GBR 5QI
        assert!(!qos.qos_id.is_empty());

        // Serialised QosData carries the mandatory qosId (pcfd-01), no qosDecId.
        let qjson = qos.to_json();
        assert_eq!(qjson["qosId"], qos.qos_id);
        assert_eq!(qjson["5qi"], 1);
        assert_eq!(qjson["maxbrDl"], "256 Kbps");
        assert!(qjson.get("qosDecId").is_none());

        // PccRule JSON references the QosData by its qosId.
        let pjson = rule.to_json();
        assert_eq!(pjson["pccRuleId"], "PccRule-af-5-1");
        assert_eq!(pjson["refQosData"][0], qos.qos_id);
        assert_eq!(pjson["flowStatus"], "ENABLED");
    }

    /// pcfd-02: a non-numeric qosReference falls back to the media-type default
    /// 5QI; a numeric qosReference overrides it; non-GBR media omit gbr.
    #[test]
    fn test_media_component_qos_ref_and_non_gbr() {
        let sess = PcfSess::new(1, 1, 7);
        let req = AscReqData {
            supp_feat: None,
            notif_uri: None,
            med_components: vec![MediaComponent {
                med_comp_n: 3,
                med_type: MediaType::Application, // default 5QI 9 (non-GBR)
                mar_bw_dl: Some("10 Mbps".to_string()),
                mar_bw_ul: Some("5 Mbps".to_string()),
                qos_ref: Some("6".to_string()), // numeric → overrides to 5QI 6
                f_status: FlowStatus::EnabledDownlink,
                med_sub_comps: vec![MediaSubComponent {
                    f_num: 1,
                    flow_usage: FlowUsage::NoInfo,
                    f_descs: vec!["permit out ip from any to assigned".to_string()],
                }],
                ..Default::default()
            }],
        };
        let rules = media_components_to_pcc(&req, &sess);
        let rule = &rules[0];
        assert_eq!(rule.qos_data.five_qi, 6); // numeric qosReference wins
        assert!(rule.qos_data.gbr_dl.is_none()); // 5QI 6 is non-GBR
        assert_eq!(rule.qos_data.maxbr_dl.as_deref(), Some("10 Mbps"));
        assert_eq!(rule.flow_status, FlowStatus::EnabledDownlink);
    }

    /// pcfd-02: the outbound SM policy update notify body carries the AF PCC
    /// rule and its QosData (captured/inspected directly).
    #[test]
    fn test_build_af_sm_policy_notification_carries_pcc_rule() {
        let mut sess = PcfSess::new(2, 1, 5);
        sess.notification_uri = Some("http://smf/cb".to_string());
        let req = AscReqData {
            supp_feat: Some("0".to_string()),
            notif_uri: Some("http://af".to_string()),
            med_components: vec![MediaComponent {
                med_comp_n: 1,
                med_type: MediaType::Video,
                mar_bw_dl: Some("2 Mbps".to_string()),
                mar_bw_ul: Some("1 Mbps".to_string()),
                f_status: FlowStatus::Enabled,
                med_sub_comps: vec![MediaSubComponent {
                    f_num: 1,
                    flow_usage: FlowUsage::NoInfo,
                    f_descs: vec!["permit out ip from any to assigned".to_string()],
                }],
                ..Default::default()
            }],
        };
        sess.af_pcc_rules = media_components_to_pcc(&req, &sess);

        let body = build_af_sm_policy_notification(&sess);
        assert!(body["resourceUri"]
            .as_str()
            .unwrap()
            .contains(&sess.sm_policy_id));
        let pcc = &body["smPolicyDecision"]["pccRules"]["PccRule-af-5-1"];
        assert_eq!(pcc["precedence"], 101);
        assert_eq!(
            pcc["flowInfos"][0]["flowDescription"],
            "permit out ip from any to assigned"
        );
        let qos_id = pcc["refQosData"][0].as_str().unwrap();
        let qos = &body["smPolicyDecision"]["qosDecs"][qos_id];
        assert_eq!(qos["qosId"], qos_id);
        assert_eq!(qos["5qi"], 2); // video → GBR 5QI 2
        assert_eq!(qos["maxbrDl"], "2 Mbps");
    }

    /// pcfd-10: VPLMN detection is driven by the serving PLMN vs. the configured
    /// local PLMN (default 001/01), not a hardcoded `false`. An empty serving
    /// PLMN is treated as home.
    #[test]
    fn test_is_serving_plmn_vplmn() {
        // Default local PLMN is 001/01 (env unset in test).
        std::env::remove_var("PCF_LOCAL_PLMN");
        // Equal to local → home (false).
        assert!(!is_serving_plmn_vplmn("001", "01"));
        // Different MCC → visited (true).
        assert!(is_serving_plmn_vplmn("310", "260"));
        // Different MNC only → visited (true).
        assert!(is_serving_plmn_vplmn("001", "99"));
        // Absent serving PLMN → home (false), preserving the H-PCF default.
        assert!(!is_serving_plmn_vplmn("", ""));
    }
}
