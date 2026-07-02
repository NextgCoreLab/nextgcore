//! SM Policy Decision builder (TS 29.512) shared between the PCF binary's
//! Npcf_SMPolicyControl handlers and library modules (`sbi_path`'s
//! SmPolicyNotification re-evaluation).
//!
//! Moved verbatim out of `main.rs` for the Wave-6 H1 lib-targetization of
//! `nextgcore-pcfd` (the library module tree must not depend on binary-root
//! items); no logic change.

use crate::{npcf_handler, nudr_handler};

/// The parts of an SmPolicyDecision (TS 29.512 §5.6.2.4)
pub struct SmPolicyDecisionParts {
    pub sess_rules: serde_json::Value,
    pub pcc_rules: serde_json::Value,
    pub qos_decs: serde_json::Value,
    /// Charging decisions referenced from PCC rules via refChgData
    pub chg_decs: serde_json::Value,
    /// Traffic-control decisions referenced from PCC rules via refTcData
    pub traff_cont_decs: serde_json::Value,
    pub triggers: Vec<String>,
}

/// Build a complete SM Policy Decision from session data (TS 29.512)
///
/// Generates session rules, PCC rules, QoS decisions, charging decisions
/// (chgDecs), traffic-control decisions (traffContDecs) and policy control
/// request triggers based on subscription data from UDR. When the
/// subscription carries no PCC rules a default match-all rule is generated
/// so that charging and traffic-control decisions always apply.
pub fn build_sm_policy_decision(
    sm_policy_id: &str,
    session_data: &nudr_handler::SessionData,
) -> SmPolicyDecisionParts {
    let sess_rule_id = format!("SessRule-{sm_policy_id}");
    let def_qos_id = format!("QosDec-{sm_policy_id}");

    let arp = arp_json(
        session_data.arp_priority_level,
        session_data.arp_preempt_cap,
        session_data.arp_preempt_vuln,
    );

    // Session rules with authorized session AMBR and the inline default QoS.
    // TS 29.512 Table 5.6.2.7-1: the default QoS is conveyed inline via
    // `authDefQos`; SessionRule has no `defQosRef` attribute (pcfd-06).
    let sess_rules = serde_json::json!({
        &sess_rule_id: {
            "sessRuleId": sess_rule_id,
            "authSessAmbr": {
                "uplink": format_bitrate(session_data.ambr_uplink),
                "downlink": format_bitrate(session_data.ambr_downlink),
            },
            "authDefQos": {
                "5qi": session_data.qos_index,
                "arp": arp.clone(),
            },
        }
    });

    // Default QoS decision
    let mut qos_map = serde_json::Map::new();
    qos_map.insert(
        def_qos_id.clone(),
        serde_json::json!({
            // TS 29.512 Table 5.6.2.8-1: qosId is the mandatory (P=M, card 1)
            // identifier; the qosDecs map key equals this value. There is no
            // qosDecId attribute in the spec.
            "qosId": def_qos_id,
            "5qi": session_data.qos_index,
            // ARP is C ("shall be included when the QoS data is initially
            // provisioned") — TS 29.512 §5.6.2.8 (pcfd-07).
            "arp": arp.clone(),
            "maxbrUl": format_bitrate(session_data.ambr_uplink),
            "maxbrDl": format_bitrate(session_data.ambr_downlink),
        }),
    );

    let mut pcc_map = serde_json::Map::new();
    let mut chg_map = serde_json::Map::new();
    let mut tc_map = serde_json::Map::new();

    // Closure: charging decision per rule (TS 29.512 §5.6.2.11 ChargingData)
    let mut add_chg_dec = |rule_key: &str, rating_group: u32| -> String {
        let chg_id = format!("ChgDec-{rule_key}");
        chg_map.insert(
            chg_id.clone(),
            serde_json::json!({
                "chgId": chg_id,
                "ratingGroup": rating_group,
                "meteringMethod": "VOLUME",
                "offline": true,
                "online": false,
            }),
        );
        chg_id
    };
    // Closure: traffic-control decision per rule (TS 29.512 §5.6.2.10)
    let mut add_tc_dec = |rule_key: &str, enabled: bool| -> String {
        let tc_id = format!("TcDec-{rule_key}");
        tc_map.insert(
            tc_id.clone(),
            serde_json::json!({
                "tcId": tc_id,
                "flowStatus": if enabled { "ENABLED" } else { "DISABLED" },
            }),
        );
        tc_id
    };

    // PCC rules from database subscription data
    for (i, rule) in session_data.pcc_rules.iter().enumerate() {
        let rule_qos_id = format!("QosDec-pcc-{}", rule.id);

        let flows: Vec<serde_json::Value> = rule
            .flows
            .iter()
            .enumerate()
            .map(|(j, f)| {
                serde_json::json!({
                    "flowDescription": f.description,
                    "flowDirection": match f.direction {
                        nudr_handler::FlowDirection::Uplink => "UPLINK",
                        nudr_handler::FlowDirection::Downlink => "DOWNLINK",
                        _ => "BIDIRECTIONAL",
                    },
                    "packFiltId": format!("pf-{}-{}", rule.id, j),
                })
            })
            .collect();

        let enabled = !matches!(
            rule.flow_status,
            npcf_handler::FlowStatus::Disabled | npcf_handler::FlowStatus::Removed
        );
        let chg_id = add_chg_dec(&rule.id, (i + 1) as u32);
        let tc_id = add_tc_dec(&rule.id, enabled);

        pcc_map.insert(
            rule.id.clone(),
            serde_json::json!({
                "pccRuleId": rule.id,
                "precedence": rule.precedence,
                "flowInfos": flows,
                "refQosData": [&rule_qos_id],
                "refChgData": [chg_id],
                "refTcData": [tc_id],
            }),
        );

        // Per-rule QoS decision. ARP is included on every provisioned QosData
        // (TS 29.512 §5.6.2.8, pcfd-07); the subscription PccRule model carries
        // no per-rule maxbr/gbr, so those are emitted only when present.
        qos_map.insert(
            rule_qos_id.clone(),
            serde_json::json!({
                // TS 29.512 Table 5.6.2.8-1: mandatory qosId (== map key).
                "qosId": rule_qos_id,
                "5qi": rule.qos_index,
                "arp": arp.clone(),
            }),
        );
    }

    // Default match-all PCC rule (lowest precedence) so charging and
    // traffic-control decisions always exist for the session.
    if session_data.pcc_rules.is_empty() {
        let rule_key = format!("default-{sm_policy_id}");
        let rule_id = format!("PccRule-{rule_key}");
        let chg_id = add_chg_dec(&rule_key, 1);
        let tc_id = add_tc_dec(&rule_key, true);
        pcc_map.insert(
            rule_id.clone(),
            serde_json::json!({
                "pccRuleId": rule_id,
                "precedence": 255,
                "flowInfos": [{
                    "flowDescription": "permit out ip from any to assigned",
                    "flowDirection": "BIDIRECTIONAL",
                    "packFiltId": format!("pf-{rule_key}-0"),
                }],
                "refQosData": [&def_qos_id],
                "refChgData": [chg_id],
                "refTcData": [tc_id],
            }),
        );
    }

    // Policy control request triggers (TS 29.512 Table 5.6.2.6-1), derived from
    // the actual decision contents (pcfd-12) rather than a static list. The base
    // set covers the session-level changes the PCF always re-evaluates; the
    // dynamic triggers are added only when the decision installs resources the
    // PCF will act on.
    let mut triggers = vec![
        "SE_AMBR_CH".to_string(), // Session AMBR change
        "DEF_QOS_CH".to_string(), // Default QoS change
        "UE_IP_CH".to_string(),   // UE IP address change
        "PLMN_CH".to_string(),    // Serving network change
        "AC_TY_CH".to_string(),   // Access type change
        "RAT_TY_CH".to_string(),  // RAT type change
    ];
    // RES_MO_RE only when subscription PCC rules are installed that the UE can
    // request to modify (a default-only session cannot UE-modify resources).
    if !session_data.pcc_rules.is_empty() {
        triggers.push("RES_MO_RE".to_string());
    }
    // QOS_NOTIF when any installed rule is a GBR resource subject to QoS
    // notification control (TS 23.501 §5.7.4 GBR 5QIs).
    if session_data
        .pcc_rules
        .iter()
        .any(|r| npcf_handler::is_gbr_5qi(r.qos_index))
    {
        triggers.push("QOS_NOTIF".to_string());
    }

    SmPolicyDecisionParts {
        sess_rules,
        pcc_rules: serde_json::Value::Object(pcc_map),
        qos_decs: serde_json::Value::Object(qos_map),
        chg_decs: serde_json::Value::Object(chg_map),
        traff_cont_decs: serde_json::Value::Object(tc_map),
        triggers,
    }
}

/// Build the TS 29.512 Arp (Allocation/Retention Priority) JSON object shared by
/// `authDefQos` and provisioned `QosData` (pcfd-07). The preemption booleans map
/// to the spec enum strings.
pub fn arp_json(priority_level: u8, preempt_cap: bool, preempt_vuln: bool) -> serde_json::Value {
    serde_json::json!({
        "priorityLevel": priority_level,
        "preemptCap": if preempt_cap { "MAY_PREEMPT" } else { "NOT_PREEMPT" },
        "preemptVuln": if preempt_vuln { "PREEMPTABLE" } else { "NOT_PREEMPTABLE" },
    })
}

/// Format bitrate as a human-readable string per 3GPP TS 29.571
pub fn format_bitrate(bps: u64) -> String {
    if bps >= 1_000_000_000 && bps.is_multiple_of(1_000_000_000) {
        format!("{} Gbps", bps / 1_000_000_000)
    } else if bps >= 1_000_000 && bps.is_multiple_of(1_000_000) {
        format!("{} Mbps", bps / 1_000_000)
    } else if bps >= 1_000 && bps.is_multiple_of(1_000) {
        format!("{} Kbps", bps / 1_000)
    } else {
        format!("{bps} bps")
    }
}
