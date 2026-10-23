//! NPCF Handler Implementation
//!
//! Port of src/pcf/npcf-handler.c - Npcf request data types and the AF
//! media-component -> PCC rule mapping used by the live handlers in `app`.
//! The C port's FSM-routed `pcf_npcf_*_handle_*` handlers were unreachable and
//! re-took the PCF context lock they held (#655), so they were deleted.

use crate::context::{AccessType, Ambr, Guami, PcfSess, RatType, SNssai};

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
    /// TS 29.514 `AppSessionContextReqData` UE-address identifiers. The schema is
    /// a `oneOf` over these three, so exactly one must be present — carried as
    /// three options rather than an enum so the parser can report "zero or more
    /// than one" rather than silently picking the first (#88).
    pub ue_ipv4: Option<String>,
    pub ue_ipv6: Option<String>,
    pub ue_mac: Option<String>,
    /// The TSC management containers a TSN AF / TSCTSF supplied (#321).
    pub tsc: TscManagementContainers,
}

/// One port's management information container (TS 29.512 / TS 29.514
/// `PortManagementContainer`), #321.
///
/// The schema marks BOTH members required, so neither is optional here: a
/// container with no port number cannot be applied to anything, and a port number
/// with no container configures nothing.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PortManagementContainer {
    /// `portManCont` — the PMIC as a TS 29.571 `Bytes`, i.e. base64.
    ///
    /// Kept base64 rather than decoded here: this PCF is a RELAY for it (TS 23.502
    /// Annex F puts the PCF between the TSCTSF and the SMF and gives it nothing to
    /// decide about the contents), and decoding then re-encoding an opaque octet
    /// string only adds a way to corrupt it.
    pub port_man_cont: String,
    /// `portNum` — TS 29.512 `TsnPortNumber`.
    pub port_num: u32,
}

/// The TSC management containers carried between the TSCTSF, the PCF and the SMF
/// (TS 29.514 `AppSessionContextReqData` → TS 29.512 `SmPolicyDecision`), #321.
///
/// The member names are IDENTICAL in both specs, which is why this one type serves
/// both the inbound parse and the outbound build.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TscManagementContainers {
    /// `tsnBridgeManCont.bridgeManCont` — the UMIC. Base64, for the same relay
    /// reason as `PortManagementContainer::port_man_cont`.
    pub bridge_man_cont: Option<String>,
    /// `tsnPortManContDstt` — the device-side (DS-TT) port's PMIC.
    pub port_man_cont_dstt: Option<PortManagementContainer>,
    /// `tsnPortManContNwtts` — one per network-side (NW-TT) port. `minItems: 1`
    /// in the schema, so an empty vector means "absent" and is not serialised.
    pub port_man_cont_nwtts: Vec<PortManagementContainer>,
    /// `tscNotifUri` — where TSC management notifications should be sent.
    pub notif_uri: Option<String>,
    /// `tscNotifCorreId`.
    pub notif_corre_id: Option<String>,
}

impl TscManagementContainers {
    /// Whether anything TSC-related was supplied at all.
    ///
    /// The whole set is optional: the overwhelming majority of app sessions are
    /// ordinary media authorisations with no TSC members, and those must not
    /// acquire a TSC leg just because the members are now parsed.
    pub fn is_empty(&self) -> bool {
        self.bridge_man_cont.is_none()
            && self.port_man_cont_dstt.is_none()
            && self.port_man_cont_nwtts.is_empty()
    }

    /// Serialise to the TS 29.512 `SmPolicyDecision` fragment carrying these
    /// containers to the SMF. Returns the members to merge, empty when there is
    /// nothing to say.
    pub fn to_decision_fragment(&self) -> serde_json::Map<String, serde_json::Value> {
        let mut out = serde_json::Map::new();
        if let Some(umic) = &self.bridge_man_cont {
            out.insert(
                "tsnBridgeManCont".to_string(),
                serde_json::json!({ "bridgeManCont": umic }),
            );
        }
        if let Some(dstt) = &self.port_man_cont_dstt {
            out.insert(
                "tsnPortManContDstt".to_string(),
                serde_json::json!({
                    "portManCont": dstt.port_man_cont,
                    "portNum": dstt.port_num,
                }),
            );
        }
        if !self.port_man_cont_nwtts.is_empty() {
            out.insert(
                "tsnPortManContNwtts".to_string(),
                serde_json::Value::Array(
                    self.port_man_cont_nwtts
                        .iter()
                        .map(|p| {
                            serde_json::json!({
                                "portManCont": p.port_man_cont,
                                "portNum": p.port_num,
                            })
                        })
                        .collect(),
                ),
            );
        }
        if let Some(uri) = &self.notif_uri {
            out.insert("tscNotifUri".to_string(), serde_json::json!(uri));
        }
        if let Some(id) = &self.notif_corre_id {
            out.insert("tscNotifCorreId".to_string(), serde_json::json!(id));
        }
        out
    }
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
            MediaType::Audio => 1,   // conversational voice (GBR)
            MediaType::Video => 2,   // conversational video / live (GBR)
            MediaType::Control => 5, // IMS signalling (non-GBR)
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

/// Durable representation (issue #66/#192): the TS 29.512 token, emitted by the
/// SAME codec the wire uses.
///
/// Delegates to [`FlowStatus::as_wire`] / [`FlowStatus::from_wire`] rather than
/// carrying `#[serde(rename)]` attributes, because those would be a second copy
/// of a token table that already exists here -- and nothing would catch the two
/// drifting apart. Contrast `AccessType` in `context.rs`, which has no existing
/// codec and so gets renames as its only table.
///
/// Note `from_wire` is lenient (an unknown token becomes `Enabled`, its TS 29.514
/// default). That is right for the wire, where a peer may send a newer value, and
/// it is also right here: a snapshot member this build does not recognise should
/// not cost the whole PCC rule.
impl serde::Serialize for FlowStatus {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_wire())
    }
}

impl<'de> serde::Deserialize<'de> for FlowStatus {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let token = <String as serde::Deserialize>::deserialize(deserializer)?;
        Ok(Self::from_wire(&token))
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
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
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
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
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
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
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
///
/// #321: also carries the TSC management containers, which is the PCF → SMF hop of
/// 5GS-TSN. TS 29.512's `SmPolicyDecision` defines `tsnBridgeManCont`,
/// `tsnPortManContDstt` and `tsnPortManContNwtts` under exactly the names
/// TS 29.514 uses on the inbound PolicyAuthorization leg, so this is a copy and
/// not a translation — there is no mapping step in which they could be corrupted.
pub fn build_af_sm_policy_notification(sess: &PcfSess) -> serde_json::Value {
    let (pcc_rules, qos_decs) = af_pcc_rules_to_decision(&sess.af_pcc_rules);
    let mut decision = serde_json::Map::new();
    decision.insert("pccRules".to_string(), pcc_rules);
    decision.insert("qosDecs".to_string(), qos_decs);
    decision.extend(sess.tsc_containers.to_decision_fragment());
    serde_json::json!({
        "resourceUri": format!("/npcf-smpolicycontrol/v1/sm-policies/{}", sess.sm_policy_id),
        "smPolicyDecision": serde_json::Value::Object(decision),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

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
            ..Default::default()
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
            ..Default::default()
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
            ..Default::default()
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
    fn test_tsc_containers_reach_the_sm_policy_decision() {
        let mut sess = PcfSess::new(7, 1, 5);
        sess.tsc_containers = TscManagementContainers {
            bridge_man_cont: Some("dW1pYw==".to_string()), // "umic"
            port_man_cont_dstt: Some(PortManagementContainer {
                port_man_cont: "ZHN0dA==".to_string(), // "dstt"
                port_num: 1,
            }),
            port_man_cont_nwtts: vec![PortManagementContainer {
                port_man_cont: "bnd0dA==".to_string(), // "nwtt"
                port_num: 7,
            }],
            notif_uri: Some("http://tsctsf.example/notify".to_string()),
            notif_corre_id: Some("corr-1".to_string()),
        };

        let body = build_af_sm_policy_notification(&sess);
        let dec = &body["smPolicyDecision"];

        assert_eq!(
            dec["tsnBridgeManCont"]["bridgeManCont"], "dW1pYw==",
            "the UMIC travels under tsnBridgeManCont.bridgeManCont"
        );
        assert_eq!(dec["tsnPortManContDstt"]["portManCont"], "ZHN0dA==");
        assert_eq!(
            dec["tsnPortManContDstt"]["portNum"], 1,
            "portNum is REQUIRED alongside portManCont (TS 29.512 PortManagementContainer)"
        );
        assert_eq!(dec["tsnPortManContNwtts"][0]["portManCont"], "bnd0dA==");
        assert_eq!(dec["tsnPortManContNwtts"][0]["portNum"], 7);
        assert_eq!(dec["tscNotifUri"], "http://tsctsf.example/notify");
        assert_eq!(dec["tscNotifCorreId"], "corr-1");

        // The PCC-rule half of the same decision is untouched, so a session with
        // both an AF media authorisation and a TSC one gets ONE notification
        // carrying both rather than two each missing half.
        assert!(dec.get("pccRules").is_some());
        assert!(dec.get("qosDecs").is_some());
    }

    /// A session with no TSC authorisation produces a decision with NO TSC members,
    /// so every ordinary AF notification is byte-identical to before #321.
    #[test]
    fn test_no_tsc_containers_adds_no_members() {
        let sess = PcfSess::new(8, 1, 5);
        let body = build_af_sm_policy_notification(&sess);
        let dec = &body["smPolicyDecision"];
        for member in [
            "tsnBridgeManCont",
            "tsnPortManContDstt",
            "tsnPortManContNwtts",
            "tscNotifUri",
            "tscNotifCorreId",
        ] {
            assert!(
                dec.get(member).is_none(),
                "{member} must be absent, not null: TS 29.512 members are optional \
                 and a null would be a value the SMF has to interpret"
            );
        }
    }

    #[test]
    fn test_tsc_containers_is_empty_ignores_notification_members_only() {
        // notifUri alone is not a configuration: a TSCTSF that sent only a callback
        // has authorised nothing to apply, so this must not count as TSC-carrying or
        // the SMF would be sent an empty modification.
        let notif_only = TscManagementContainers {
            notif_uri: Some("http://x/y".to_string()),
            ..Default::default()
        };
        assert!(notif_only.is_empty());

        let with_umic = TscManagementContainers {
            bridge_man_cont: Some("dW1pYw==".to_string()),
            ..Default::default()
        };
        assert!(!with_umic.is_empty());
    }
}
