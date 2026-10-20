//! #515 stage 3: the generated E-CID Measurement Report decode against the
//! pre-change hand-written one, and TS 38.413 §10 applied to it.

use super::*;
use nextgcore_asn1c::nrppa::ies::ProtocolIeField;
use nextgcore_asn1c::nrppa::ies::{
    ECidMeasurementResult, MeasuredResults, MeasuredResultsValue, NgRanCell, NgRanCgi,
    PlmnIdentity, ResultRsrpEutraItem, ResultRsrqEutraItem, Tac, UeMeasurementId,
};
use nextgcore_asn1c::nrppa::pdu::{
    build_ecid_measurement_report, InitiatingMessageValue, NrppaPdu,
};
use nextgcore_asn1c::nrppa::types::{Criticality, NrppaTransactionId, ProtocolIeId};

fn result(cell: NgRanCell, values: Option<Vec<MeasuredResultsValue>>) -> ECidMeasurementResult {
    ECidMeasurementResult {
        serving_cell_id: NgRanCgi {
            plmn_identity: PlmnIdentity([0x02, 0xf8, 0x39]),
            ng_ran_cell: cell,
        },
        serving_cell_tac: Tac([0x00, 0x12, 0x34]),
        ng_ran_access_point_position: None,
        measured_results: values.map(|values| MeasuredResults { values }),
    }
}

fn report(lmf: u16, ran: u16, r: &ECidMeasurementResult) -> NrppaPdu {
    build_ecid_measurement_report(
        NrppaTransactionId(9),
        UeMeasurementId(lmf),
        UeMeasurementId(ran),
        r,
        None,
    )
    .unwrap()
}

fn rsrp(values: &[u8]) -> MeasuredResultsValue {
    MeasuredResultsValue::ResultRsrp(
        values
            .iter()
            .map(|v| ResultRsrpEutraItem {
                pci_eutra: 42,
                earfcn: 1850,
                value_rsrp_eutra: *v,
            })
            .collect(),
    )
}

fn rsrq(values: &[u8]) -> MeasuredResultsValue {
    MeasuredResultsValue::ResultRsrq(
        values
            .iter()
            .map(|v| ResultRsrqEutraItem {
                pci_eutra: 42,
                earfcn: 1850,
                value_rsrq_eutra: *v,
            })
            .collect(),
    )
}

fn accepted(bytes: &[u8]) -> (u64, Vec<CellMeasurement>, Option<Vec<u8>>) {
    match decode_ecid_report(bytes).expect("an E-CID report") {
        EcidReportOutcome::Accepted {
            lmf_measurement_id,
            cells,
            error_indication,
        } => (lmf_measurement_id, cells, error_indication),
        other => panic!("expected the report to be accepted, got {other:?}"),
    }
}

/// Every report shape the hand-written decoder accepted decodes to the same
/// measurement id and cells, with no ERROR INDICATION.
#[test]
fn accepted_reports_match_the_hand_written_decode() {
    let cells = [
        NgRanCell::NrCellId(0),
        NgRanCell::NrCellId(1),
        NgRanCell::NrCellId((1u64 << 36) - 1),
        NgRanCell::EutraCellId(0),
        NgRanCell::EutraCellId((1u32 << 28) - 1),
    ];
    let measured = [
        None,
        Some(vec![MeasuredResultsValue::ValueTimingAdvanceType1(0)]),
        Some(vec![MeasuredResultsValue::ValueTimingAdvanceType2(7690)]),
        Some(vec![MeasuredResultsValue::ValueAngleOfArrival(719)]),
        Some(vec![rsrp(&[0]), rsrp(&[97, 60])]),
        Some(vec![rsrq(&[34, 3]), rsrq(&[20])]),
        Some(vec![
            MeasuredResultsValue::ValueTimingAdvanceType1(500),
            MeasuredResultsValue::ValueTimingAdvanceType2(9),
            MeasuredResultsValue::ValueAngleOfArrival(90),
            rsrp(&[60, 55]),
            rsrq(&[10]),
        ]),
    ];
    let mut n = 0;
    for cell in &cells {
        for m in &measured {
            for (lmf, ran) in [(1u16, 1u16), (15, 7), (16, 256), (200, 3)] {
                let bytes = report(lmf, ran, &result(*cell, m.clone()))
                    .encode()
                    .unwrap();
                let (id, got, ei) = accepted(&bytes);
                let (want_id, want) =
                    crate::codec_glue::decode_nrppa_ecid_report_hand_written(&bytes).unwrap();
                assert_eq!(id, want_id);
                assert_eq!(format!("{got:?}"), format!("{want:?}"), "{cell:?} {m:?}");
                assert!(ei.is_none());
                n += 1;
            }
        }
    }
    assert_eq!(n, 5 * 7 * 4);
}

/// Splice one extra IE with `id` and `criticality` into a valid report.
fn with_unknown_ie(id: u16, criticality: Criticality) -> Vec<u8> {
    let mut pdu = report(
        3,
        5,
        &result(NgRanCell::NrCellId(1), Some(vec![rsrp(&[60])])),
    );
    let NrppaPdu::InitiatingMessage(m) = &mut pdu else {
        unreachable!()
    };
    let InitiatingMessageValue::ECidMeasurementReport(c) = &mut m.value else {
        unreachable!()
    };
    c.push(ProtocolIeField {
        id: ProtocolIeId(id),
        criticality,
        value: vec![0x00],
    });
    pdu.encode().unwrap().to_vec()
}

fn parse_ei(bytes: &[u8]) -> (u8, Vec<(u8, u16, u8)>, u16) {
    let nrppa::NRPPA_PDU::InitiatingMessage(m) = nextgcore_nrppa_gen::decode(bytes).unwrap() else {
        panic!("not an initiating message");
    };
    assert_eq!(m.procedure_code.0, nrppa::ID_ERROR_INDICATION);
    assert_eq!(m.criticality.0, IGNORE);
    let nrppa::InitiatingMessageValue::Id_errorIndication(ei) = m.value else {
        panic!("not an ERROR INDICATION");
    };
    let mut cause = None;
    let mut list = vec![];
    let mut diag_txn = None;
    for ie in ei.protocol_i_es.0 {
        match ie.value {
            nrppa::ErrorIndicationProtocolIEs_EntryValue::Id_Cause(nrppa::Cause::Protocol(c)) => {
                cause = Some(c.0)
            }
            nrppa::ErrorIndicationProtocolIEs_EntryValue::Id_CriticalityDiagnostics(d) => {
                assert_eq!(
                    d.procedure_code.unwrap().0,
                    nrppa::ID_E_CID_MEASUREMENT_REPORT
                );
                assert_eq!(
                    d.triggering_message.unwrap().0,
                    nrppa::TriggeringMessage::INITIATING_MESSAGE
                );
                diag_txn = d.nrppatransaction_id.map(|t| t.0);
                list = d
                    .i_es_criticality_diagnostics
                    .unwrap()
                    .0
                    .into_iter()
                    .map(|e| (e.ie_criticality.0, e.ie_id.0, e.type_of_error.0))
                    .collect();
            }
            other => panic!("unexpected IE {other:?}"),
        }
    }
    assert_eq!(
        m.nrppatransaction_id.0,
        diag_txn.expect("TS 38.455 §10: the transaction id")
    );
    (cause.expect("a protocol cause"), list, diag_txn.unwrap())
}

#[test]
fn an_unknown_ignore_ie_is_dropped_silently() {
    let (id, cells, ei) = accepted(&with_unknown_ie(9999, Criticality::Ignore));
    assert_eq!(id, 3);
    assert_eq!(cells.len(), 1);
    assert!(ei.is_none());
}

#[test]
fn an_unknown_notify_ie_is_processed_and_reported() {
    let (id, cells, ei) = accepted(&with_unknown_ie(9999, Criticality::Notify));
    assert_eq!((id, cells.len()), (3, 1));
    let (cause, list, txn) = parse_ei(&ei.expect("an ERROR INDICATION"));
    assert_eq!(
        cause,
        nrppa::CauseProtocol::ABSTRACT_SYNTAX_ERROR_IGNORE_AND_NOTIFY
    );
    assert_eq!(
        list,
        vec![(NOTIFY, 9999, nrppa::TypeOfError::NOT_UNDERSTOOD)]
    );
    assert_eq!(txn, 9);
}

#[test]
fn an_unknown_reject_ie_rejects_the_report_and_is_reported() {
    let outcome = decode_ecid_report(&with_unknown_ie(9999, Criticality::Reject)).unwrap();
    let EcidReportOutcome::Rejected {
        error_indication, ..
    } = outcome
    else {
        panic!("a reject IE must reject the report, got {outcome:?}");
    };
    let (cause, list, _) = parse_ei(&error_indication);
    assert_eq!(cause, nrppa::CauseProtocol::ABSTRACT_SYNTAX_ERROR_REJECT);
    assert_eq!(
        list,
        vec![(REJECT, 9999, nrppa::TypeOfError::NOT_UNDERSTOOD)]
    );
    // The hand-written decoder, for comparison, accepted it as if the IE were absent.
    assert!(
        crate::codec_glue::decode_nrppa_ecid_report_hand_written(&with_unknown_ie(
            9999,
            Criticality::Reject
        ))
        .is_ok()
    );
}

/// Drop the IE with `id` from a valid report.
fn without_ie(id: u16) -> Vec<u8> {
    let mut pdu = report(
        3,
        5,
        &result(NgRanCell::NrCellId(1), Some(vec![rsrp(&[60])])),
    );
    let NrppaPdu::InitiatingMessage(m) = &mut pdu else {
        unreachable!()
    };
    let InitiatingMessageValue::ECidMeasurementReport(c) = &mut m.value else {
        unreachable!()
    };
    c.ies.retain(|f| f.id.0 != id);
    pdu.encode().unwrap().to_vec()
}

#[test]
fn a_missing_measurement_id_rejects_the_report_and_is_reported_missing() {
    for id in [
        nrppa::ID_LMF_UE_MEASUREMENT_ID,
        nrppa::ID_RAN_UE_MEASUREMENT_ID,
    ] {
        let EcidReportOutcome::Rejected {
            error_indication, ..
        } = decode_ecid_report(&without_ie(id)).unwrap()
        else {
            panic!("a missing reject IE {id} must reject the report");
        };
        let (cause, list, _) = parse_ei(&error_indication);
        assert_eq!(cause, nrppa::CauseProtocol::ABSTRACT_SYNTAX_ERROR_REJECT);
        assert_eq!(list, vec![(REJECT, id, nrppa::TypeOfError::MISSING)]);
    }
}

#[test]
fn a_missing_measurement_result_is_ignored() {
    let (id, cells, ei) = accepted(&without_ie(nrppa::ID_E_CID_MEASUREMENT_RESULT));
    assert_eq!(id, 3);
    assert!(cells.is_empty(), "nothing to measure from");
    assert!(ei.is_none(), "criticality ignore: no report");
}

#[test]
fn a_pdu_that_is_not_an_ecid_report_is_an_error() {
    let (_, request) = crate::nrppa_downlink::build_ecid_measurement_initiation(1).unwrap();
    assert!(decode_ecid_report(&request).is_err());
    assert!(decode_ecid_report(&[0xff, 0x00]).is_err());
}
