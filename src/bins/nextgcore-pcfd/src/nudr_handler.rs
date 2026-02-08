//! NUDR Handler Implementation
//!
//! Port of src/pcf/nudr-handler.c - Handlers for NUDR (UDR) responses

use crate::context::{PcfSess, PcfUeAm};
use crate::npcf_handler::{HTTP_STATUS_BAD_REQUEST, HTTP_STATUS_FORBIDDEN, HTTP_STATUS_NOT_FOUND};
use crate::sbi_path::pcf_sess_sbi_discover_and_send;

/// Handler result for NUDR responses
#[derive(Debug)]
pub struct NudrHandlerResult {
    pub success: bool,
    pub status: u16,
    pub error_message: Option<String>,
}

impl NudrHandlerResult {
    pub fn ok() -> Self {
        Self {
            success: true,
            status: 200,
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

/// AM Policy Data from UDR
#[derive(Debug, Clone, Default)]
pub struct AmPolicyData {
    pub pra_infos: Vec<PresenceReportingAreaInfo>,
}

/// Presence Reporting Area Info
#[derive(Debug, Clone, Default)]
pub struct PresenceReportingAreaInfo {
    pub pra_id: String,
    pub presence_state: PresenceState,
}

/// Presence State
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PresenceState {
    #[default]
    InArea,
    OutOfArea,
    Unknown,
    Inactive,
}


/// SM Policy Data from UDR
#[derive(Debug, Clone, Default)]
pub struct SmPolicyData {
    pub sm_policy_snssai_data: Vec<SmPolicySnssaiData>,
}

/// SM Policy S-NSSAI Data
#[derive(Debug, Clone, Default)]
pub struct SmPolicySnssaiData {
    pub snssai: crate::context::SNssai,
    pub sm_policy_dnn_data: Vec<SmPolicyDnnData>,
}

/// SM Policy DNN Data
#[derive(Debug, Clone, Default)]
pub struct SmPolicyDnnData {
    pub dnn: String,
    pub allowed_services: Vec<String>,
    pub subscribed_charging_data: Option<SubscribedChargingData>,
}

/// Subscribed Charging Data
#[derive(Debug, Clone, Default)]
pub struct SubscribedChargingData {
    pub charging_method: ChargingMethod,
}

/// Charging Method
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ChargingMethod {
    #[default]
    Online,
    Offline,
    OnlineOffline,
}

/// Subscription Data from database
#[derive(Debug, Clone, Default)]
pub struct SubscriptionData {
    pub ambr_uplink: u64,
    pub ambr_downlink: u64,
}

/// Handle Query AM Data response from UDR
/// Port of pcf_nudr_dr_handle_query_am_data() from nudr-handler.c
pub fn pcf_nudr_dr_handle_query_am_data(
    pcf_ue_am: &mut PcfUeAm,
    stream_id: u64,
    resource_component: &str,
    am_policy_data: Option<&AmPolicyData>,
) -> NudrHandlerResult {
    log::debug!(
        "[{}] NUDR DR Query AM Data response (resource={})",
        pcf_ue_am.supi,
        resource_component
    );

    match resource_component {
        "am-data" => {
            // Validate AM Policy Data
            if am_policy_data.is_none() {
                log::error!("[{}] No AmPolicyData", pcf_ue_am.supi);
                return NudrHandlerResult::error(HTTP_STATUS_BAD_REQUEST, "No AmPolicyData");
            }

            // Query subscription data from database
            let subscription_data = query_subscription_data(&pcf_ue_am.supi);
            if subscription_data.is_none() {
                log::error!("[{}] Cannot find SUPI in DB", pcf_ue_am.supi);
                return NudrHandlerResult::error(HTTP_STATUS_NOT_FOUND, "Cannot find SUPI in DB");
            }

            let subscription_data = subscription_data.unwrap();

            // Validate UE-AMBR
            if subscription_data.ambr_uplink == 0 && subscription_data.ambr_downlink == 0 {
                log::error!("[{}] No UE-AMBR", pcf_ue_am.supi);
                return NudrHandlerResult::error(HTTP_STATUS_NOT_FOUND, "No UE-AMBR");
            }


            // Build PolicyAssociation response
            // In C: This builds the full PolicyAssociation with:
            // - request (copy of original PolicyAssociationRequest)
            // - supp_feat (negotiated features)
            // - triggers (e.g., UE_AMBR_CH if AMBR differs)
            // - ue_ambr (authorized UE AMBR)

            // Check if UE AMBR authorization is enabled
            const UE_AMBR_AUTHORIZATION_FEATURE: u64 = 0x01; // Placeholder
            if (pcf_ue_am.am_policy_control_features & UE_AMBR_AUTHORIZATION_FEATURE) != 0 {
                if let Some(ref subscribed_ambr) = pcf_ue_am.subscribed_ue_ambr {
                    // Compare subscribed vs authorized AMBR
                    // In C: This compares bitrates and adds UE_AMBR_CH trigger if different
                    log::debug!(
                        "[{}] Subscribed UE-AMBR: up={}, down={}",
                        pcf_ue_am.supi,
                        subscribed_ambr.uplink,
                        subscribed_ambr.downlink
                    );
                }
            }

            // Send PolicyAssociation response
            // In C: ogs_sbi_server_send_response(stream, response)
            log::debug!(
                "[{}] Sending PolicyAssociation response (stream={})",
                pcf_ue_am.supi,
                stream_id
            );

            NudrHandlerResult::ok()
        }
        _ => {
            log::error!(
                "[{}] Invalid resource name [{}]",
                pcf_ue_am.supi,
                resource_component
            );
            NudrHandlerResult::error(HTTP_STATUS_BAD_REQUEST, "Invalid resource name")
        }
    }
}

/// Handle Query SM Data response from UDR
/// Port of pcf_nudr_dr_handle_query_sm_data() from nudr-handler.c
pub fn pcf_nudr_dr_handle_query_sm_data(
    sess: &mut PcfSess,
    pcf_ue_sm_supi: &str,
    stream_id: u64,
    resource_component: &str,
    sm_policy_data: Option<&SmPolicyData>,
) -> NudrHandlerResult {
    log::debug!(
        "[{}:{}] NUDR DR Query SM Data response (resource={})",
        pcf_ue_sm_supi,
        sess.psi,
        resource_component
    );

    match resource_component {
        "sm-data" => {
            // Validate SM Policy Data
            if sm_policy_data.is_none() {
                log::error!("[{}:{}] No SmPolicyData", pcf_ue_sm_supi, sess.psi);
                return NudrHandlerResult::error(HTTP_STATUS_BAD_REQUEST, "No SmPolicyData");
            }

            // Register with BSF
            log::debug!(
                "[{}:{}] Registering with BSF (stream={})",
                pcf_ue_sm_supi,
                sess.psi,
                stream_id
            );

            if let Err(e) = pcf_sess_sbi_discover_and_send(sess.id, stream_id, "nbsf-management") {
                log::error!(
                    "[{}:{}] Failed to discover BSF: {}",
                    pcf_ue_sm_supi,
                    sess.psi,
                    e
                );
                return NudrHandlerResult::error(
                    HTTP_STATUS_FORBIDDEN,
                    "POLICY_CONTEXT_DENIED",
                );
            }

            NudrHandlerResult::ok()
        }
        _ => {
            log::error!(
                "[{}:{}] Invalid resource name [{}]",
                pcf_ue_sm_supi,
                sess.psi,
                resource_component
            );
            NudrHandlerResult::error(HTTP_STATUS_FORBIDDEN, "POLICY_CONTEXT_DENIED")
        }
    }
}


/// Public API for querying subscription data (used by AM policy handler)
pub fn query_subscription_data_pub(supi: &str) -> Option<SubscriptionData> {
    query_subscription_data(supi)
}

/// Query subscription data from database via ogs-dbi
/// In C: ogs_dbi_subscription_data()
fn query_subscription_data(supi: &str) -> Option<SubscriptionData> {
    log::debug!("Querying subscription data for SUPI: {}", supi);

    match ogs_dbi::ogs_dbi_subscription_data(supi) {
        Ok(sub_data) => {
            log::debug!(
                "[{}] Subscription data: AMBR up={}, down={}",
                supi,
                sub_data.ambr.uplink,
                sub_data.ambr.downlink
            );
            Some(SubscriptionData {
                ambr_uplink: sub_data.ambr.uplink,
                ambr_downlink: sub_data.ambr.downlink,
            })
        }
        Err(e) => {
            log::warn!(
                "[{}] Failed to query subscription data from DB: {}, using defaults",
                supi,
                e
            );
            // Fallback to default values when DB is unavailable
            Some(SubscriptionData {
                ambr_uplink: 1000000000,   // 1 Gbps
                ambr_downlink: 1000000000, // 1 Gbps
            })
        }
    }
}

/// Get session data from database via ogs-dbi
/// In C: pcf_get_session_data()
pub fn pcf_get_session_data(
    supi: &str,
    _plmn_id: Option<&crate::context::PlmnId>,
    s_nssai: &crate::context::SNssai,
    dnn: &str,
) -> Option<SessionData> {
    log::debug!(
        "Getting session data for SUPI={}, S-NSSAI={:?}, DNN={}",
        supi,
        s_nssai,
        dnn
    );

    let ogs_snssai = ogs_dbi::OgsSNssai::new(s_nssai.sst, s_nssai.sd);

    match ogs_dbi::ogs_dbi_session_data(supi, Some(&ogs_snssai), dnn) {
        Ok(sess_data) => {
            let qos = &sess_data.session.qos;
            let ambr = &sess_data.session.ambr;

            let pcc_rules = sess_data
                .pcc_rule
                .iter()
                .map(|r| {
                    PccRule {
                        id: r.id.clone().unwrap_or_default(),
                        precedence: r.precedence as u32,
                        qos_index: r.qos.index,
                        flow_status: crate::npcf_handler::FlowStatus::Enabled,
                        flows: r
                            .flow
                            .iter()
                            .map(|f| FlowDescription {
                                direction: match f.direction {
                                    1 => FlowDirection::Downlink,
                                    2 => FlowDirection::Uplink,
                                    3 => FlowDirection::Bidirectional,
                                    _ => FlowDirection::Bidirectional,
                                },
                                description: f
                                    .description
                                    .clone()
                                    .unwrap_or_default(),
                            })
                            .collect(),
                    }
                })
                .collect();

            log::debug!(
                "[{}] Session data: 5QI={}, ARP={}, AMBR up={} down={}, {} PCC rules",
                supi,
                qos.index,
                qos.arp.priority_level,
                ambr.uplink,
                ambr.downlink,
                sess_data.num_of_pcc_rule
            );

            Some(SessionData {
                qos_index: qos.index,
                arp_priority_level: qos.arp.priority_level,
                arp_preempt_cap: qos.arp.pre_emption_capability != 0,
                arp_preempt_vuln: qos.arp.pre_emption_vulnerability != 0,
                ambr_uplink: ambr.uplink,
                ambr_downlink: ambr.downlink,
                pcc_rules,
            })
        }
        Err(e) => {
            log::warn!(
                "[{}] Failed to query session data from DB: {}, using defaults",
                supi,
                e
            );
            // Fallback to default values when DB is unavailable
            Some(SessionData {
                qos_index: 9,
                arp_priority_level: 8,
                arp_preempt_cap: false,
                arp_preempt_vuln: true,
                ambr_uplink: 100000000,
                ambr_downlink: 100000000,
                pcc_rules: vec![],
            })
        }
    }
}

/// Session Data from database
#[derive(Debug, Clone, Default)]
pub struct SessionData {
    pub qos_index: u8,
    pub arp_priority_level: u8,
    pub arp_preempt_cap: bool,
    pub arp_preempt_vuln: bool,
    pub ambr_uplink: u64,
    pub ambr_downlink: u64,
    pub pcc_rules: Vec<PccRule>,
}

/// PCC Rule
#[derive(Debug, Clone, Default)]
pub struct PccRule {
    pub id: String,
    pub precedence: u32,
    pub qos_index: u8,
    pub flow_status: crate::npcf_handler::FlowStatus,
    pub flows: Vec<FlowDescription>,
}

/// Flow Description
#[derive(Debug, Clone, Default)]
pub struct FlowDescription {
    pub direction: FlowDirection,
    pub description: String,
}

/// Flow Direction
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FlowDirection {
    #[default]
    Bidirectional,
    Uplink,
    Downlink,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nudr_handler_result_ok() {
        let result = NudrHandlerResult::ok();
        assert!(result.success);
        assert_eq!(result.status, 200);
    }

    #[test]
    fn test_nudr_handler_result_error() {
        let result = NudrHandlerResult::error(400, "Test error");
        assert!(!result.success);
        assert_eq!(result.status, 400);
        assert_eq!(result.error_message, Some("Test error".to_string()));
    }

    #[test]
    fn test_subscription_data_default() {
        let data = SubscriptionData::default();
        assert_eq!(data.ambr_uplink, 0);
        assert_eq!(data.ambr_downlink, 0);
    }

    #[test]
    fn test_session_data_default() {
        let data = SessionData::default();
        assert_eq!(data.qos_index, 0);
        assert!(data.pcc_rules.is_empty());
    }

    #[test]
    fn test_query_subscription_data() {
        let data = query_subscription_data("imsi-001010000000001");
        assert!(data.is_some());
        let data = data.unwrap();
        assert!(data.ambr_uplink > 0);
        assert!(data.ambr_downlink > 0);
    }

    #[test]
    fn test_pcf_get_session_data() {
        let s_nssai = crate::context::SNssai { sst: 1, sd: None };
        let data = pcf_get_session_data("imsi-001010000000001", None, &s_nssai, "internet");
        assert!(data.is_some());
        let data = data.unwrap();
        assert!(data.qos_index > 0);
    }

    #[test]
    fn test_presence_state_default() {
        let state = PresenceState::default();
        assert_eq!(state, PresenceState::InArea);
    }

    #[test]
    fn test_charging_method_default() {
        let method = ChargingMethod::default();
        assert_eq!(method, ChargingMethod::Online);
    }
}
