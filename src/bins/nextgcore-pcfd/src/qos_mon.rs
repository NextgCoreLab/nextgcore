//! The PCF's authorised QoS monitoring policy for packet delay (#2221).
//!
//! TS 23.503 §6.1.3.21: the PCF "generates the authorized QoS Monitoring policy
//! for the service data flow based on local policy and/or AF request". This module
//! turns an AF's QoS monitoring subscription (TS 29.514 §4.2.2.23.1,
//! `EventsSubscReqData` with a `QOS_MONITORING` event, `reqQosMonParams` and
//! `qosMon`) into a TS 29.512 `QosMonitoringData` instance (§4.2.3.25.1, §5.6.2.40),
//! referenced from the session's AF PCC rules by `refQosMon`, with
//! `QOS_MONITORING` among the policy control request triggers, so the SMF reports
//! the measurements to this PCF (§4.2.4.24). Those reports go on to the AF in an
//! `EventsNotification` with `qosMonReports` (TS 29.514 §4.2.5.14).
//!
//! Only packet delay: QoSMonitoring (SM policy feature 24, PA feature 16), and
//! PacketDelayFailureReport (SM policy feature 73, PA feature 44), which makes an
//! EVENT_DETECTION `repPeriod` the maximum period with no measurement reported
//! and lets a report carry `pdmf`. Only the AF session level subscription
//! (§4.2.2.23.1, `evSubsc` of the app session); not modelled, stated: a
//! subscription per media sub-component, EnQoSMon (data rate, congestion,
//! available bitrate), direct notification (`directNotifInd`, `notifyUri` in the
//! instance: the reports always come to this PCF), and local policy (the PCF
//! authorises what the AF asked for, nothing of its own).

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// TS 29.512 Table 5.8-1 feature 24, QosMonitoring.
pub const SM_FEATURE_QOS_MONITORING: u64 = 1 << 23;
/// TS 29.512 Table 5.8-1 feature 73, PacketDelayFailureReport: past the 64 bits
/// of the PCF's SM feature mask, so negotiated on its own ([`has_feature`]).
pub const SM_FEATURE_NUMBER_PACKET_DELAY_FAILURE_REPORT: u32 = 73;
/// TS 29.514 Table 5.8-1 feature 16, QoSMonitoring.
pub const PA_FEATURE_QOS_MONITORING: u64 = 1 << 15;
/// TS 29.514 Table 5.8-1 feature 44, PacketDelayFailureReport.
pub const PA_FEATURE_PACKET_DELAY_FAILURE_REPORT: u64 = 1 << 43;

/// The QoS monitoring policy one AF app session holds on its PDU session.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AfQosMon {
    /// The `qmId` of the instance (and its key in `qosMonDecs`).
    pub qm_id: String,
    /// The `QosMonitoringData` as sent to the SMF.
    pub data: Value,
    /// The app session whose subscription asked for it: the reports go there.
    pub app_session_id: String,
    /// The PCC rules of that app session, which reference the instance.
    pub pcc_rule_ids: Vec<String>,
}

/// The `qmId` of app session `app_session_id`'s instance.
pub fn qm_id_for(app_session_id: &str) -> String {
    format!("QosMon-{app_session_id}")
}

/// Whether the TS 29.571 §5.2.2 SupportedFeatures hex string `s` sets feature
/// `n` (1-based: feature 1 is the least significant bit of the last character),
/// whatever the string's length. A string that is not all hex sets nothing.
pub fn has_feature(s: Option<&str>, n: u32) -> bool {
    let Some(s) = s
        .map(str::trim)
        .filter(|s| s.bytes().all(|b| b.is_ascii_hexdigit()))
    else {
        return false;
    };
    let (idx, bit) = (((n - 1) / 4) as usize, (n - 1) % 4);
    s.len() > idx
        && char::from(s.as_bytes()[s.len() - 1 - idx])
            .to_digit(16)
            .is_some_and(|d| d & (1 << bit) != 0)
}

/// `hex` (a negotiated SupportedFeatures, lowercase, at most 64 bits) with
/// feature `n` set as well.
pub fn with_feature(hex: &str, n: u32) -> String {
    let low = u128::from_str_radix(hex, 16).unwrap_or(0);
    format!("{:x}", low | (1u128 << (n - 1)))
}

/// The `QosMonitoringData` (TS 29.512 §5.6.2.40) an AF's `EventsSubscReqData`
/// asks for (TS 29.514 §4.2.2.23.1), `None` when it has no packet-delay
/// QOS_MONITORING subscription:
/// - `reqQosMonParams` as the AF gave them (DOWNLINK, UPLINK, ROUND_TRIP);
/// - one `repFreqs` per QOS_MONITORING event: PERIODIC for a PERIODIC
///   `notifMethod`, EVENT_TRIGGERED for EVENT_DETECTION;
/// - `repPeriod` / `waitTime` from those events, and the thresholds from `qosMon`.
///
/// An EVENT_DETECTION event's `repPeriod` is the maximum period with no QoS
/// measurement reported, which exists only under PacketDelayFailureReport, so it
/// is passed on only when `pdfr` (negotiated with both the AF and the SMF).
pub fn policy_from_subscription(qm_id: &str, subsc: &Value, pdfr: bool) -> Option<Value> {
    let events: Vec<&Value> = subsc
        .get("events")?
        .as_array()?
        .iter()
        .filter(|e| e.get("event").and_then(Value::as_str) == Some("QOS_MONITORING"))
        .filter(|e| {
            e.get("qosMonParamType")
                .and_then(Value::as_str)
                .is_none_or(|t| t == "PACKET_DELAY")
        })
        .collect();
    if events.is_empty() {
        return None;
    }
    let params: Vec<Value> = subsc
        .get("reqQosMonParams")?
        .as_array()?
        .iter()
        .filter(|p| {
            matches!(
                p.as_str(),
                Some("DOWNLINK") | Some("UPLINK") | Some("ROUND_TRIP")
            )
        })
        .cloned()
        .collect();
    if params.is_empty() {
        return None;
    }
    let mut freqs = Vec::new();
    let mut data = serde_json::json!({ "qmId": qm_id, "reqQosMonParams": params });
    for e in &events {
        match e.get("notifMethod").and_then(Value::as_str) {
            Some("PERIODIC") => {
                freqs.push("PERIODIC");
                if let Some(p) = e.get("repPeriod") {
                    data["repPeriod"] = p.clone();
                }
            }
            Some("EVENT_DETECTION") => {
                freqs.push("EVENT_TRIGGERED");
                if let Some(w) = e.get("waitTime") {
                    data["waitTime"] = w.clone();
                }
                if pdfr && data.get("repPeriod").is_none() {
                    if let Some(p) = e.get("repPeriod") {
                        data["repPeriod"] = p.clone();
                    }
                }
            }
            _ => {}
        }
    }
    if freqs.is_empty() {
        return None;
    }
    freqs.dedup();
    data["repFreqs"] = serde_json::json!(freqs);
    if freqs.contains(&"EVENT_TRIGGERED") {
        let mon = subsc.get("qosMon")?;
        for k in ["repThreshDl", "repThreshUl", "repThreshRp"] {
            if let Some(v) = mon.get(k).filter(|v| !v.is_null()) {
                data[k] = v.clone();
            }
        }
    }
    Some(data)
}

/// The `medCompN` of an AF PCC rule (`PccRule-af-<psi>-<medCompN>`,
/// [`crate::npcf_handler::media_components_to_pcc`]).
fn med_comp_n(pcc_rule_id: &str) -> Option<u64> {
    pcc_rule_id
        .strip_prefix("PccRule-af-")?
        .rsplit('-')
        .next()?
        .parse()
        .ok()
}

/// The SMF's `QosMonitoringReport`s (TS 29.512 §5.6.2.42) as the AF's (TS 29.514
/// §5.6.2.37): `refPccRuleIds` become the `flows` of those rules' media
/// components, only the rules of `rule_ids` (the app session's) count, and a
/// `pdmf` is passed on only when `pdfr` (PacketDelayFailureReport negotiated with
/// the AF). A report left with no rule of the app session or nothing measured is
/// dropped.
pub fn af_reports(reports: &[Value], rule_ids: &[String], pdfr: bool) -> Vec<Value> {
    let mut out = Vec::new();
    for r in reports {
        let mut comps: Vec<u64> = r
            .get("refPccRuleIds")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .filter(|id| rule_ids.iter().any(|own| own == id))
            .filter_map(med_comp_n)
            .collect();
        comps.sort_unstable();
        comps.dedup();
        if comps.is_empty() {
            continue;
        }
        let mut rep = serde_json::Map::new();
        for k in ["ulDelays", "dlDelays", "rtDelays"] {
            if let Some(v) = r
                .get(k)
                .filter(|v| v.as_array().is_some_and(|a| !a.is_empty()))
            {
                rep.insert(k.to_string(), v.clone());
            }
        }
        if pdfr {
            if let Some(v) = r.get("pdmf").filter(|v| v.is_boolean()) {
                rep.insert("pdmf".to_string(), v.clone());
            }
        }
        if rep.is_empty() {
            continue;
        }
        rep.insert(
            "flows".to_string(),
            comps
                .iter()
                .map(|n| serde_json::json!({ "medCompN": n }))
                .collect(),
        );
        out.push(Value::Object(rep));
    }
    out
}

/// The AF `EventsNotification` (TS 29.514 §4.2.5.14) carrying `reports`
/// ([`af_reports`]) for app session `app_session_id`.
pub fn af_notification(app_session_id: &str, reports: &[Value]) -> Value {
    serde_json::json!({
        "evSubsUri": format!(
            "/npcf-policyauthorization/v1/app-sessions/{app_session_id}/events-subscription"
        ),
        "evNotifs": [{ "event": "QOS_MONITORING" }],
        "qosMonReports": reports,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// TS 29.514 §4.2.2.23.1 to TS 29.512 §4.2.3.25.1: PERIODIC carries
    /// `repPeriod`, EVENT_DETECTION carries `waitTime` and the `qosMon`
    /// thresholds; both events make both frequencies.
    #[test]
    fn an_af_subscription_becomes_a_qos_monitoring_data_instance_2221() {
        let d = policy_from_subscription(
            "qm",
            &json!({
                "events": [
                    { "event": "QOS_MONITORING", "notifMethod": "PERIODIC", "repPeriod": 5 },
                    { "event": "QOS_MONITORING", "notifMethod": "EVENT_DETECTION", "waitTime": 2 },
                    { "event": "USAGE_REPORT" },
                ],
                "reqQosMonParams": ["DOWNLINK", "ROUND_TRIP", "DOWNLINK_CONGESTION"],
                "qosMon": { "repThreshDl": 20, "repThreshRp": 40 },
            }),
            false,
        )
        .unwrap();
        assert_eq!(d["qmId"], "qm");
        assert_eq!(d["reqQosMonParams"], json!(["DOWNLINK", "ROUND_TRIP"]));
        assert_eq!(d["repFreqs"], json!(["PERIODIC", "EVENT_TRIGGERED"]));
        assert_eq!(
            (d["repPeriod"].clone(), d["waitTime"].clone()),
            (json!(5), json!(2))
        );
        assert_eq!(
            (d["repThreshDl"].clone(), d["repThreshRp"].clone()),
            (json!(20), json!(40))
        );
        assert!(d.get("repThreshUl").is_none());
    }

    /// No QOS_MONITORING event, no packet-delay parameter, another parameter
    /// type, or EVENT_DETECTION without `qosMon`: no instance.
    #[test]
    fn what_is_not_a_packet_delay_request_makes_no_instance_2221() {
        let periodic = json!({ "event": "QOS_MONITORING", "notifMethod": "PERIODIC" });
        for s in [
            json!({ "events": [{ "event": "USAGE_REPORT" }], "reqQosMonParams": ["UPLINK"] }),
            json!({ "events": [periodic.clone()], "reqQosMonParams": ["UPLINK_DATA_RATE"] }),
            json!({ "events": [periodic.clone()] }),
            json!({ "events": [{ "event": "QOS_MONITORING", "notifMethod": "PERIODIC", "qosMonParamType": "CONGESTION" }], "reqQosMonParams": ["UPLINK"] }),
            json!({ "events": [{ "event": "QOS_MONITORING", "notifMethod": "EVENT_DETECTION" }], "reqQosMonParams": ["UPLINK"] }),
        ] {
            assert_eq!(policy_from_subscription("qm", &s, true), None, "{s}");
        }
    }

    /// An EVENT_DETECTION `repPeriod` (the maximum period with no measurement)
    /// is passed on only under PacketDelayFailureReport; a PERIODIC one always.
    #[test]
    fn an_event_triggered_rep_period_needs_packet_delay_failure_report_2221() {
        let s = json!({
            "events": [{ "event": "QOS_MONITORING", "notifMethod": "EVENT_DETECTION", "repPeriod": 30 }],
            "reqQosMonParams": ["UPLINK"],
            "qosMon": { "repThreshUl": 10 },
        });
        assert!(policy_from_subscription("qm", &s, false)
            .unwrap()
            .get("repPeriod")
            .is_none());
        assert_eq!(
            policy_from_subscription("qm", &s, true).unwrap()["repPeriod"],
            30
        );
    }

    /// TS 29.571 §5.2.2: feature 1 is the last character's least significant
    /// bit, whatever the string's length; 73 is past 64 bits.
    #[test]
    fn features_are_read_from_the_end_of_the_string_2221() {
        assert!(has_feature(Some("800000"), 24));
        assert!(!has_feature(Some("400000"), 24));
        let f73 = format!("1{}", "0".repeat(18));
        assert!(has_feature(Some(&f73), 73));
        assert!(!has_feature(Some(&f73[1..]), 73));
        assert!(!has_feature(Some("zz"), 1));
        assert!(!has_feature(None, 1));
        assert_eq!(
            with_feature("800003", 73),
            format!("1{}800003", "0".repeat(12))
        );
        assert_eq!(SM_FEATURE_QOS_MONITORING, 1 << 23);
        assert_eq!(PA_FEATURE_QOS_MONITORING, 1 << 15);
    }

    /// TS 29.512 §5.6.2.42 to TS 29.514 §5.6.2.37: the app session's rules become
    /// `flows`; another app session's rule, or a report with nothing measured, is
    /// not passed on; `pdmf` only under PacketDelayFailureReport.
    #[test]
    fn an_smf_report_becomes_the_af_s_2221() {
        let own = vec!["PccRule-af-5-1".to_string(), "PccRule-af-5-2".to_string()];
        let reports = vec![
            json!({ "refPccRuleIds": ["PccRule-af-5-2", "PccRule-af-5-1", "PccRule-af-5-9"], "dlDelays": [13], "rtDelays": [27] }),
            json!({ "refPccRuleIds": ["PccRule-af-5-9"], "ulDelays": [1] }),
            json!({ "refPccRuleIds": ["PccRule-af-5-1"], "pdmf": true }),
        ];
        assert_eq!(
            af_reports(&reports, &own, false),
            vec![
                json!({ "flows": [{ "medCompN": 1 }, { "medCompN": 2 }], "dlDelays": [13], "rtDelays": [27] })
            ]
        );
        assert_eq!(
            af_reports(&reports, &own, true)[1],
            json!({ "flows": [{ "medCompN": 1 }], "pdmf": true })
        );
    }
}
