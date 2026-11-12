//! #1390 unit tests: the N2, N4 and notification encodings QOS_MON relies on.

use super::*;
use crate::n2_transfer::{self, Arp, QosFlowSetup};
use nextgcore_ngap_gen::generated as g;

fn flow(qos_monitoring: Option<QosMonitoringRequest>) -> QosFlowSetup {
    QosFlowSetup {
        qfi: 9,
        five_qi: 9,
        arp: Arp::default_flow(8),
        gbr: None,
        e_rab_id: None,
        qos_monitoring,
    }
}

/// The QoS Monitoring Request(s) of each flow of a Modify Request Transfer, as
/// the generated (TS 38.413 ASN.1) decoder reads them, with their criticality.
fn monitoring_of(transfer: &[u8]) -> Vec<(u8, Vec<(u8, u8)>)> {
    let t = nextgcore_ngap_gen::decode_contained::<g::PDUSessionResourceModifyRequestTransfer>(
        transfer,
    )
    .expect("decodes");
    let mut out = Vec::new();
    for ie in t.protocol_i_es.0 {
        if let g::PDUSessionResourceModifyRequestTransferProtocolIEs_EntryValue::Id_QosFlowAddOrModifyRequestList(l) = ie.value {
            for item in l.0 {
                let exts = item
                    .qos_flow_level_qos_parameters
                    .and_then(|p| p.ie_extensions)
                    .map(|e| e.0)
                    .unwrap_or_default();
                let reqs = exts
                    .into_iter()
                    .filter_map(|e| match e.extension_value {
                        g::QosFlowLevelQosParametersIE_Extensions_EntryExtensionValue::Id_QosMonitoringRequest(r) => {
                            assert_eq!(e.id.0, 181, "id-QosMonitoringRequest");
                            Some((r.0, e.criticality.0))
                        }
                        _ => None,
                    })
                    .collect();
                out.push((item.qos_flow_identifier.0, reqs));
            }
        }
    }
    out
}

#[test]
fn the_modify_request_transfer_carries_id_181_on_the_flow() {
    let both = n2_transfer::modify_request_transfer_with_qos(
        (1000, 1000),
        &[flow(Some(QosMonitoringRequest::Both))],
    )
    .unwrap();
    assert_eq!(
        monitoring_of(&both),
        vec![(
            9,
            vec![(g::QosMonitoringRequest::BOTH, g::Criticality::IGNORE)]
        )]
    );
    let stop = n2_transfer::modify_request_transfer_with_qos(
        (1000, 1000),
        &[flow(Some(QosMonitoringRequest::Stop))],
    )
    .unwrap();
    assert_eq!(
        monitoring_of(&stop),
        vec![(
            9,
            vec![(g::QosMonitoringRequest::STOP, g::Criticality::IGNORE)]
        )]
    );
    // Not monitored: no extension, so the transfer is what it was before #1390.
    let plain = n2_transfer::modify_request_transfer_with_qos((1000, 1000), &[flow(None)]).unwrap();
    assert_eq!(monitoring_of(&plain), vec![(9, vec![])]);
    assert!(plain.len() < both.len());
}

#[test]
fn the_setup_request_transfer_carries_id_181_when_monitored() {
    let req = |m| n2_transfer::SetupRequest {
        ambr: Some((1000, 1000)),
        ul_tunnel: (0x11, [10, 0, 0, 1]),
        data_forwarding_not_possible: false,
        direct_forwarding_path_availability: false,
        flows: vec![flow(m)],
    };
    let both = n2_transfer::setup_request_transfer(&req(Some(QosMonitoringRequest::Both))).unwrap();
    let plain = n2_transfer::setup_request_transfer(&req(None)).unwrap();
    let t =
        nextgcore_ngap_gen::decode_contained::<g::PDUSessionResourceSetupRequestTransfer>(&both)
            .unwrap();
    let found = t.protocol_i_es.0.into_iter().any(|ie| {
        matches!(ie.value, g::PDUSessionResourceSetupRequestTransferProtocolIEs_EntryValue::Id_QosFlowSetupRequestList(l)
            if l.0[0].qos_flow_level_qos_parameters.ie_extensions.as_ref().is_some_and(|e| matches!(
                e.0[0].extension_value,
                g::QosFlowLevelQosParametersIE_Extensions_EntryExtensionValue::Id_QosMonitoringRequest(g::QosMonitoringRequest(v)) if v == g::QosMonitoringRequest::BOTH
            )))
    });
    assert!(
        found,
        "the default flow's QoS parameters carry id 181 = both"
    );
    assert!(plain.len() < both.len());
}

/// The top-level IEs of an N4 message body.
fn top(body: &[u8]) -> Vec<(u16, Vec<u8>)> {
    let mut out = Vec::new();
    let mut at = 0;
    while at + 4 <= body.len() {
        let t = u16::from_be_bytes([body[at], body[at + 1]]);
        let l = u16::from_be_bytes([body[at + 2], body[at + 3]]) as usize;
        out.push((t, body[at + 4..at + 4 + l].to_vec()));
        at += 4 + l;
    }
    out
}

#[test]
fn create_and_remove_srr_are_table_7_5_2_9_1_and_7_5_4_19_1() {
    let body = crate::n4_build::build_session_modification_request(
        &crate::n4_build::SessionModificationParams {
            create_srrs: vec![(3, vec![control_for(9, 5)])],
            remove_srr_ids: vec![2],
            ..Default::default()
        },
    );
    let ies = top(&body);
    let remove = ies.iter().find(|(t, _)| *t == 211).expect("Remove SRR");
    assert_eq!(remove.1, vec![0, 215, 0, 1, 2], "SRR ID 2");
    let create = ies.iter().find(|(t, _)| *t == 212).expect("Create SRR");
    let members = top(&create.1);
    assert_eq!(members[0], (215, vec![3]), "SRR ID first");
    let ctl = QosMonitoringPerQosFlowControlInformation::decode_value(&members[1].1).unwrap();
    assert_eq!(members[1].0, 242);
    assert_eq!(ctl, control_for(9, 5));
    assert_eq!(ctl.qfis, vec![9]);
    assert!(ctl.requested_qos_monitoring.dlpd && ctl.requested_qos_monitoring.ulpd);
    assert!(ctl.requested_qos_monitoring.rppd && !ctl.requested_qos_monitoring.gtpupm);
    assert!(ctl.reporting_frequency.perio);
    assert_eq!(ctl.measurement_period, Some(5));
    // Nothing asked: neither IE (the modification is what it was before #1390).
    let none = crate::n4_build::build_session_modification_request(&Default::default());
    assert!(top(&none).iter().all(|(t, _)| *t != 211 && *t != 212));
}

/// A Session Report Request body with SESR as upfd sends it (#1451).
pub(crate) fn sesr_body(srr_id: u8, m: QosMonitoringMeasurement) -> Vec<u8> {
    let mut b = vec![0, 39, 0, 1, 0x20];
    let mut sr = vec![0, 215, 0, 1, srr_id];
    let mut v = bytes::BytesMut::new();
    QosMonitoringReport {
        qfi: 9,
        qos_monitoring_measurement: m,
        time_stamp: 0xe8a0_0000,
        start_time: None,
        extra: Vec::new(),
    }
    .encode_ie(&mut v);
    sr.extend_from_slice(&v);
    b.extend_from_slice(&214u16.to_be_bytes());
    b.extend_from_slice(&(sr.len() as u16).to_be_bytes());
    b.extend_from_slice(&sr);
    b
}

#[test]
fn a_session_report_s_qos_monitoring_reports_are_read_by_srr() {
    let m = QosMonitoringMeasurement {
        downlink_packet_delay: Some(22),
        uplink_packet_delay: Some(23),
        round_trip_packet_delay: Some(45),
        ..Default::default()
    };
    let got = reports_in(&sesr_body(4, m));
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].0, 4);
    assert_eq!(got[0].1.qos_monitoring_measurement, m);
    assert!(reports_in(&[0, 39, 0, 1, 0x20]).is_empty());
}

#[test]
fn a_qos_mon_notification_has_one_delay_each_or_pdmf() {
    let sub = event_exposure::parse_subscription(
        &serde_json::json!({
            "notifId": "n-1390", "notifUri": "http://127.0.0.1:1/cb",
            "eventSubs": [{ "event": "QOS_MON" }], "supi": "imsi-001010000001390",
            "notifMethod": "PERIODIC", "repPeriod": 4,
        }),
        "s".into(),
    )
    .unwrap();
    assert_eq!(event_exposure::periodic_rep_period(&sub), Some(4));
    let m = QosMonitoringMeasurement {
        downlink_packet_delay: Some(22),
        uplink_packet_delay: Some(23),
        round_trip_packet_delay: Some(45),
        ..Default::default()
    };
    let n =
        event_exposure::build_qos_mon_notification(&sub, "imsi-001010000001390", 5, &result_of(&m));
    let e = &n["eventNotifs"][0];
    assert_eq!(n["notifId"], "n-1390");
    assert_eq!(e["event"], "QOS_MON");
    assert_eq!(e["pduSeId"], 5);
    assert_eq!(e["dlDelays"], serde_json::json!([22]));
    assert_eq!(e["ulDelays"], serde_json::json!([23]));
    assert_eq!(e["rtDelays"], serde_json::json!([45]));
    assert!(e.get("pdmf").is_none());
    let f = QosMonitoringMeasurement {
        packet_delay_measurement_failure: true,
        ..Default::default()
    };
    let n =
        event_exposure::build_qos_mon_notification(&sub, "imsi-001010000001390", 5, &result_of(&f));
    let e = &n["eventNotifs"][0];
    assert_eq!(e["pdmf"], true);
    assert!(e.get("dlDelays").is_none());
    // Not PERIODIC: the default period.
    let on_event = event_exposure::parse_subscription(
        &serde_json::json!({ "notifId": "x", "notifUri": "http://h/", "eventSubs": [{ "event": "QOS_MON" }] }),
        "t".into(),
    )
    .unwrap();
    assert_eq!(event_exposure::periodic_rep_period(&on_event), None);
}
