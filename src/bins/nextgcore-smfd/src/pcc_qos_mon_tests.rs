//! #2208 unit tests: the PCF's QosMonitoringData as the PSA's IE 242, the
//! decision deltas, and where a report goes.

use super::*;
use crate::policy::parse_qos_mon_delta;
use serde_json::json;

fn periodic() -> Value {
    json!({
        "qmId": "qm1",
        "reqQosMonParams": ["DOWNLINK", "UPLINK", "ROUND_TRIP"],
        "repFreqs": ["PERIODIC"],
        "repPeriod": 4,
    })
}

/// TS 29.512 §4.2.3.25.1 to TS 29.244 Table 7.5.2.9-3: the requested parameters
/// are DLPD/ULPD/RPPD, the frequencies EVETT/PERIO, `repPeriod` the Measurement
/// Period, the thresholds and `waitTime` go only with EVETT, and GTPUPM is the
/// method's (TS 29.244 §8.2.167 bit 4).
#[test]
fn a_qos_monitoring_data_instance_is_the_psa_s_ie_242_2208() {
    let p = parse_policy(&periodic()).unwrap();
    let c = p.control(9, false);
    assert_eq!(c.qfis, vec![9]);
    let q = c.requested_qos_monitoring;
    assert!(q.dlpd && q.ulpd && q.rppd && !q.gtpupm);
    assert!(c.reporting_frequency.perio && !c.reporting_frequency.evett);
    assert_eq!(c.measurement_period, Some(4));
    assert_eq!(c.packet_delay_thresholds, None);
    assert_eq!(c.minimum_wait_time, None);
    assert!(p.control(9, true).requested_qos_monitoring.gtpupm, "GTPUPM");

    let ev = parse_policy(&json!({
        "reqQosMonParams": ["DOWNLINK", "ROUND_TRIP"],
        "repFreqs": ["EVENT_TRIGGERED"],
        "repThreshDl": 20, "repThreshRp": 50, "repThreshUl": 99,
        "waitTime": 3, "repPeriod": 30,
        "notifyUri": "http://af.example/qm", "notifyCorreId": "c-1",
    }))
    .unwrap();
    let c = ev.control(5, true);
    let q = c.requested_qos_monitoring;
    assert!(q.dlpd && !q.ulpd && q.rppd && q.gtpupm);
    assert!(c.reporting_frequency.evett && !c.reporting_frequency.perio);
    assert_eq!(
        c.packet_delay_thresholds,
        Some(PacketDelayThresholds {
            downlink: Some(20),
            uplink: None,
            round_trip: Some(50),
        }),
        "only the thresholds of requested parameters"
    );
    assert_eq!(c.minimum_wait_time, Some(3));
    assert_eq!(c.measurement_period, Some(30), "the PLMF period (item f)");
    assert_eq!(
        ev.notify,
        Some(("http://af.example/qm".into(), Some("c-1".into())))
    );
}

/// What the SMF cannot act on is refused by name: another parameter type,
/// nothing measurable, no frequency, or EVENT_TRIGGERED without the threshold of
/// a parameter it names (§4.2.3.25.1 a).
#[test]
fn an_instance_the_smf_cannot_act_on_is_refused_2208() {
    let cases = [
        (
            json!({ "qosMonParamType": "CONGESTION", "reqQosMonParams": ["DOWNLINK_CONGESTION"], "repFreqs": ["EVENT_TRIGGERED"] }),
            "not packet delay",
        ),
        (
            json!({ "reqQosMonParams": ["DOWNLINK_DATA_RATE"], "repFreqs": ["PERIODIC"] }),
            "names no DOWNLINK",
        ),
        (
            json!({ "reqQosMonParams": ["DOWNLINK"], "repFreqs": [] }),
            "neither EVENT_TRIGGERED",
        ),
        (
            json!({ "reqQosMonParams": ["UPLINK"], "repFreqs": ["EVENT_TRIGGERED"] }),
            "without repThreshUl",
        ),
    ];
    for (v, why) in cases {
        let e = parse_policy(&v).unwrap_err();
        assert!(e.contains(why), "{v}: {e}");
    }
    assert!(parse_policy(&json!({
        "qosMonParamType": "PACKET_DELAY", "reqQosMonParams": ["UPLINK"], "repFreqs": ["PERIODIC"],
    }))
    .is_ok());
}

/// TS 29.512 §4.2.6.1 on one session: a PCC rule's `refQosMon` makes the instance
/// a requester; a modified instance keeps what it does not restate (RFC 7396); a
/// `null` refQosMon, a removed rule, a removed instance and `qosMonDecs: null`
/// each end it.
#[test]
fn decisions_are_applied_as_deltas_2208() {
    let _q = crate::qos_mon::TEST_LOCK.blocking_lock();
    let _pcc = PccForTest::on();
    clear_for_test();
    let r = "ref-2208-delta";
    let first = json!({
        "pccRules": { "r1": { "refQosMon": ["qm1"] }, "r2": { "precedence": 3 } },
        "qosMonDecs": { "qm1": periodic() },
    });
    assert!(apply(r, &parse_qos_mon_delta(&first)));
    assert_eq!(requesters(r), vec!["pcc:qm1".to_string()]);
    assert_eq!(rules_of(r, "qm1"), vec!["r1".to_string()]);

    // A modified instance: only repPeriod restated.
    let modified = json!({ "qosMonDecs": { "qm1": { "repPeriod": 8 } } });
    assert!(apply(r, &parse_qos_mon_delta(&modified)));
    let p = policy(r, "qm1").unwrap();
    assert_eq!(p.rep_period, Some(8));
    assert!(p.dl && p.ul && p.rp && p.periodic, "the rest is kept");

    // A rule without refQosMon changes nothing; the same delta again neither.
    assert!(!apply(
        r,
        &parse_qos_mon_delta(&json!({ "pccRules": { "r1": { "precedence": 9 } } }))
    ));
    assert!(!apply(r, &parse_qos_mon_delta(&modified)));

    // A second rule on the same instance; one goes, the instance stays.
    apply(
        r,
        &parse_qos_mon_delta(&json!({ "pccRules": { "r2": { "refQosMon": ["qm1"] } } })),
    );
    assert_eq!(rules_of(r, "qm1"), vec!["r1".to_string(), "r2".to_string()]);
    assert!(!apply(
        r,
        &parse_qos_mon_delta(&json!({ "pccRules": { "r2": null } }))
    ));
    assert_eq!(requesters(r), vec!["pcc:qm1".to_string()]);

    // refQosMon null: no rule references it.
    assert!(apply(
        r,
        &parse_qos_mon_delta(&json!({ "pccRules": { "r1": { "refQosMon": null } } }))
    ));
    assert!(requesters(r).is_empty());

    // Referenced again, then the instance removed, then all of them.
    apply(r, &parse_qos_mon_delta(&first));
    assert!(apply(
        r,
        &parse_qos_mon_delta(&json!({ "qosMonDecs": { "qm1": null } }))
    ));
    assert!(requesters(r).is_empty());
    apply(r, &parse_qos_mon_delta(&first));
    assert!(apply(
        r,
        &parse_qos_mon_delta(&json!({ "qosMonDecs": null }))
    ));
    assert!(requesters(r).is_empty());

    // An instance the SMF cannot act on is no requester.
    apply(
        r,
        &parse_qos_mon_delta(&json!({
            "pccRules": { "r1": { "refQosMon": ["qm2"] } },
            "qosMonDecs": { "qm2": { "reqQosMonParams": ["UPLINK"], "repFreqs": ["EVENT_TRIGGERED"] } },
        })),
    );
    assert!(requesters(r).is_empty());

    forget(r);
    assert!(rules_of(r, "qm2").is_empty());
}

/// TS 29.512 §4.2.3.25.1: a report goes to the instance's notifyUri when it has
/// one (the SMF bypassing the PCF), else to the PCF when it provisioned
/// QOS_MONITORING, else nowhere.
#[test]
fn a_report_goes_to_the_notify_uri_else_the_pcf_else_nowhere_2208() {
    let _q = crate::qos_mon::TEST_LOCK.blocking_lock();
    let _pcc = PccForTest::on();
    clear_for_test();
    let r = "ref-2208-target";
    apply(
        r,
        &parse_qos_mon_delta(&json!({
            "pccRules": { "r1": { "refQosMon": ["qm1"] } },
            "qosMonDecs": { "qm1": periodic() },
        })),
    );
    assert_eq!(target(r, "qm1"), Target::Nobody);
    apply(
        r,
        &parse_qos_mon_delta(&json!({ "policyCtrlReqTriggers": ["PLMN_CH", "QOS_MONITORING"] })),
    );
    assert_eq!(target(r, "qm1"), Target::Pcf);
    apply(
        r,
        &parse_qos_mon_delta(
            &json!({ "qosMonDecs": { "qm1": { "notifyUri": "http://nef/n", "notifyCorreId": "k" } } }),
        ),
    );
    assert_eq!(
        target(r, "qm1"),
        Target::Notify("http://nef/n".into(), Some("k".into()))
    );
    // The trigger list replaced without QOS_MONITORING, the URI removed.
    apply(
        r,
        &parse_qos_mon_delta(&json!({
            "policyCtrlReqTriggers": ["PLMN_CH"],
            "qosMonDecs": { "qm1": { "notifyUri": null, "notifyCorreId": null } },
        })),
    );
    assert_eq!(target(r, "qm1"), Target::Nobody);
    forget(r);
}

/// TS 29.512 Table 5.6.2.42-1: one element per delay, the PCC rules in
/// `refPccRuleIds`, and `pdmf` only when PacketDelayFailureReport was negotiated
/// (feature 73 in the create answer's `suppFeat`). TS 29.508: the direct
/// notification's `notifId` is the `notifyCorreId`.
#[test]
fn the_reports_carry_one_delay_each_and_pdmf_only_when_negotiated_2208() {
    let _q = crate::qos_mon::TEST_LOCK.blocking_lock();
    let _pcc = PccForTest::on();
    clear_for_test();
    let r = "ref-2208-report";
    apply(
        r,
        &parse_qos_mon_delta(&json!({
            "pccRules": { "r1": { "refQosMon": ["qm1"] }, "r0": { "refQosMon": ["qm1"] } },
            "qosMonDecs": { "qm1": periodic() },
            "suppFeat": "800100",
        })),
    );
    let delays = QosMonResult {
        ul_delay: Some(7),
        dl_delay: Some(6),
        rt_delay: Some(13),
        failure: false,
    };
    assert_eq!(
        pcf_report(r, "qm1", &delays).unwrap(),
        json!({ "refPccRuleIds": ["r0", "r1"], "ulDelays": [7], "dlDelays": [6], "rtDelays": [13] })
    );
    let failure = QosMonResult {
        failure: true,
        ..Default::default()
    };
    assert_eq!(
        pcf_report(r, "qm1", &failure),
        None,
        "no PDFR: nothing to report"
    );
    apply(
        r,
        &parse_qos_mon_delta(&json!({ "suppFeat": "1000000000000800100" })),
    );
    assert_eq!(pcf_report(r, "qm1", &failure).unwrap()["pdmf"], json!(true));

    let n = direct_notification(Some("corr-9"), "imsi-001010000022080", 5, &delays, false).unwrap();
    assert_eq!(n["notifId"], "corr-9");
    let e = &n["eventNotifs"][0];
    assert_eq!(e["event"], "QOS_MON");
    assert_eq!(e["supi"], "imsi-001010000022080");
    assert_eq!(e["pduSeId"], 5);
    assert_eq!(e["dlDelays"], json!([6]));
    assert_eq!(e["rtDelays"], json!([13]));
    assert!(e["timeStamp"].is_string());
    forget(r);
}

/// The method is the operator's (TS 23.501 §5.33.3.1): `per_qos_flow` unless
/// `smf.qos_monitoring.method` says `gtpu_path`; any other value fails startup.
#[test]
fn the_method_is_configured_and_per_qos_flow_by_default_2208() {
    let y: QosMonitoringYaml = serde_yaml::from_str("{}").unwrap();
    assert_eq!(y.method, Method::PerQosFlow);
    let y: QosMonitoringYaml = serde_yaml::from_str("method: gtpu_path").unwrap();
    assert_eq!(y.method, Method::GtpuPath);
    assert!(serde_yaml::from_str::<QosMonitoringYaml>("method: per_path").is_err());
    assert!(serde_yaml::from_str::<QosMonitoringYaml>("methd: gtpu_path").is_err());
}

/// #2208 review M1: with `smf.qos_monitoring.pcc` off (the default) a decision's
/// QoS monitoring members are not acted on, so nothing is requested on N4 or N2;
/// and the SM policy create offers what it did before (feature 9 only).
#[test]
fn the_pcf_policy_is_off_by_default_2208() {
    let _q = crate::qos_mon::TEST_LOCK.blocking_lock();
    clear_for_test();
    assert!(!enabled(), "off by default");
    assert_eq!(crate::policy::sm_policy_supported_features(), "100");
    let r = "ref-2208-off";
    let d = parse_qos_mon_delta(&json!({
        "pccRules": { "r1": { "refQosMon": ["qm1"] } },
        "qosMonDecs": { "qm1": periodic() },
        "policyCtrlReqTriggers": ["QOS_MONITORING"],
    }));
    assert!(!apply(r, &d), "not acted on");
    assert!(requesters(r).is_empty());
    let _pcc = PccForTest::on();
    assert_eq!(
        crate::policy::sm_policy_supported_features(),
        crate::policy::SMF_SM_POLICY_SUPPORTED_FEATURES_QOS_MON
    );
    assert!(apply(r, &d));
    assert_eq!(requesters(r), vec!["pcc:qm1".to_string()]);
    forget(r);
}

/// #2208 review minor 1, TS 29.244 Table 7.5.2.9-3 and §5.24.4.2: with EVETT the
/// Minimum Wait Time and the Measurement Period are present whatever the PCF
/// left out: `waitTime` else 0, `repPeriod` else the default period.
#[test]
fn an_event_triggered_ie_242_always_has_its_c_ies_2208() {
    let p = parse_policy(&json!({
        "reqQosMonParams": ["ROUND_TRIP"],
        "repFreqs": ["EVENT_TRIGGERED"],
        "repThreshRp": 30,
    }))
    .unwrap();
    let c = p.control(9, false);
    assert_eq!(c.minimum_wait_time, Some(0));
    assert_eq!(c.measurement_period, Some(DEFAULT_PERIOD_SECS));
    let p = parse_policy(&json!({
        "reqQosMonParams": ["ROUND_TRIP"],
        "repFreqs": ["EVENT_TRIGGERED"],
        "repThreshRp": 30, "waitTime": 5, "repPeriod": 20,
    }))
    .unwrap();
    let c = p.control(9, false);
    assert_eq!(
        (c.minimum_wait_time, c.measurement_period),
        (Some(5), Some(20))
    );
}
