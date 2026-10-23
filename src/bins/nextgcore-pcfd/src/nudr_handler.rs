//! NUDR Handler Implementation
//!
//! Port of src/pcf/nudr-handler.c - UDR policy/subscription data types and
//! lookups used by the live handlers in `app`. The C port's FSM-routed
//! `pcf_nudr_dr_handle_query_*` handlers were unreachable (#655) and deleted.

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

/// Public API for querying subscription data (used by AM policy handler)
pub fn query_subscription_data_pub(supi: &str) -> Option<SubscriptionData> {
    query_subscription_data(supi)
}

/// Query subscription data from database via nextgcore-dbi
/// In C: nextgcore_dbi_subscription_data()
fn query_subscription_data(supi: &str) -> Option<SubscriptionData> {
    log::debug!("Querying subscription data for SUPI: {supi}");

    match nextgcore_dbi::nextgcore_dbi_subscription_data(supi) {
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
            log::warn!("[{supi}] Failed to query subscription data from DB: {e}, using defaults");
            // Fallback to default values when DB is unavailable
            Some(SubscriptionData {
                ambr_uplink: 1000000000,   // 1 Gbps
                ambr_downlink: 1000000000, // 1 Gbps
            })
        }
    }
}

/// Get session data from database via nextgcore-dbi
/// In C: pcf_get_session_data()
pub fn pcf_get_session_data(
    supi: &str,
    _plmn_id: Option<&crate::context::PlmnId>,
    s_nssai: &crate::context::SNssai,
    dnn: &str,
) -> Option<SessionData> {
    log::debug!("Getting session data for SUPI={supi}, S-NSSAI={s_nssai:?}, DNN={dnn}");

    let nextgcore_snssai = nextgcore_dbi::NextgcoreSNssai::new(s_nssai.sst, s_nssai.sd);

    match nextgcore_dbi::nextgcore_dbi_session_data(supi, Some(&nextgcore_snssai), dnn) {
        Ok(sess_data) => {
            let qos = &sess_data.session.qos;
            let ambr = &sess_data.session.ambr;

            let pcc_rules = sess_data
                .pcc_rule
                .iter()
                .map(|r| PccRule {
                    id: r.id.clone().expect("value expected"),
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
                            description: f.description.clone().expect("value expected"),
                        })
                        .collect(),
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
            log::warn!("[{supi}] Failed to query session data from DB: {e}, using defaults");
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
    fn test_charging_method_default() {
        let method = ChargingMethod::default();
        assert_eq!(method, ChargingMethod::Online);
    }
}
