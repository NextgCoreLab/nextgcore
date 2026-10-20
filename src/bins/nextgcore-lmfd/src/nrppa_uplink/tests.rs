//! #515: the E-CID Measurement Report decode on the generated codec, pinned to
//! hand-derived X.691 octets and expected measurements, and TS 38.413 §10 applied.
//! (Until the hand-written NRPPa codec was deleted it was the oracle here; stage 3
//! showed both decoders agree on 140 report shapes.)

use super::test_support::*;
use super::*;

const PLMN: [u8; 3] = [0x02, 0xf8, 0x39];
const TAC: [u8; 3] = [0x00, 0x12, 0x34];

/// E-CID Measurement Report, derived by hand from X.691 / TS 38.455: transaction
/// 9, LMF measurement id 3, RAN measurement id 5, serving cell NR 1 in PLMN
/// 02 f8 39, TAC 00 12 34, one RSRP item (PCI 42, EARFCN 1850, value 60).
///
/// ```text
/// 00 04 40 00 09 27     initiatingMessage, procedure 4, ignore, transaction 9, length 39
///  00 00 03             ext 0 + pad; 3 IEs
///  00 02 00 01 10       LMF-UE-Measurement-ID, reject; ext 0, 3-1 in 4 bits
///  00 06 00 01 20       RAN-UE-Measurement-ID, reject; ext 0, 5-1
///  00 07 40 16          E-CID-MeasurementResult, ignore; 22 octets:
///   20                  ext 0, opts 0 1 0 (measuredResults); NG-RAN-CGI ext 0, opt 0; pad
///   02 f8 39            pLMN-Identity (SIZE 3, aligned)
///   40 00 00 00 00 10   NG-RANCell index 1 of 3, pad; NRCellIdentifier 36 bits = 1, pad
///   00 12 34            servingCellTAC
///   01 80               SIZE(1..64) 0 (6 bits); CHOICE resultRSRP-EUTRA 3 of 6 (3 bits);
///                       SIZE(1..9) 0 (4 bits); item ext 0, opts 0 0
///   00 00 2a            pCI-EUTRA 42: INTEGER (0..503, ...), so ext 0 + pad, then
///                       2-octet aligned
///   20 07 3a            EARFCN ext 0, octet count-1 = 1 (2 bits), pad; 1850
///   3c                  valueRSRP-EUTRA ext 0, 60 in 7 bits
/// ```
const ECID_REPORT: [u8; 45] = [
    0x00, 0x04, 0x40, 0x00, 0x09, 0x27, 0x00, 0x00, 0x03, 0x00, 0x02, 0x00, 0x01, 0x10, 0x00, 0x06,
    0x00, 0x01, 0x20, 0x00, 0x07, 0x40, 0x16, 0x20, 0x02, 0xf8, 0x39, 0x40, 0x00, 0x00, 0x00, 0x00,
    0x10, 0x00, 0x12, 0x34, 0x01, 0x80, 0x00, 0x00, 0x2a, 0x20, 0x07, 0x3a, 0x3c,
];

fn report() -> Vec<u8> {
    ecid_report(9, 3, 5, nr_cgi(PLMN, 1), TAC, Some(vec![rsrp(&[60])]))
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

#[test]
fn the_report_encodes_to_the_hand_derived_octets_and_decodes() {
    assert_eq!(report(), ECID_REPORT);
    let (id, cells, ei) = accepted(&ECID_REPORT);
    assert_eq!(id, 3);
    assert!(ei.is_none());
    assert_eq!(cells.len(), 1);
    assert_eq!(cells[0].nr_cgi, "02f839-000000001");
    assert_eq!(cells[0].rsrp, Some(-80), "value 60 -> 60 - 140 dBm");
    assert_eq!(
        (cells[0].rsrq, cells[0].timing_advance, cells[0].aoa),
        (None, None, None)
    );
}

/// The adapter: serving-cell spelling and each measured quantity's mapping,
/// over the edges of every value range.
#[test]
fn measured_results_map_to_cell_measurements() {
    let cell = |cgi, measured| {
        let (_, cells, _) = accepted(&ecid_report(1, 15, 7, cgi, TAC, measured));
        cells.into_iter().next().expect("one serving-cell entry")
    };
    assert_eq!(cell(nr_cgi(PLMN, 0), None).nr_cgi, "02f839-000000000");
    assert_eq!(
        cell(nr_cgi(PLMN, (1 << 36) - 1), None).nr_cgi,
        "02f839-fffffffff"
    );
    assert_eq!(cell(eutra_cgi(PLMN, 0), None).nr_cgi, "02f839-e0000000");
    assert_eq!(
        cell(eutra_cgi(PLMN, (1 << 28) - 1), None).nr_cgi,
        "02f839-efffffff"
    );

    let c = cell(nr_cgi(PLMN, 1), Some(vec![ta1(0)]));
    assert_eq!(c.timing_advance, Some(0));
    let c = cell(nr_cgi(PLMN, 1), Some(vec![ta2(7690)]));
    assert_eq!(c.timing_advance, Some(7690));
    let c = cell(nr_cgi(PLMN, 1), Some(vec![aoa(719)]));
    assert_eq!(c.aoa, Some(719.0));
    // RSRP: strongest item of each list, strongest list wins; 0..97 -> -140..-43.
    let c = cell(nr_cgi(PLMN, 1), Some(vec![rsrp(&[0]), rsrp(&[97, 60])]));
    assert_eq!(c.rsrp, Some(-43));
    // RSRQ: strongest item of the FIRST list.
    let c = cell(nr_cgi(PLMN, 1), Some(vec![rsrq(&[3, 34]), rsrq(&[20])]));
    assert_eq!(c.rsrq, Some(34));
    // TA: the first TA value wins; everything together.
    let c = cell(
        nr_cgi(PLMN, 1),
        Some(vec![
            ta1(500),
            ta2(9),
            aoa(90),
            rsrp(&[60, 55]),
            rsrq(&[10]),
        ]),
    );
    assert_eq!(
        (c.timing_advance, c.aoa, c.rsrp, c.rsrq),
        (Some(500), Some(90.0), Some(-80), Some(10))
    );
}

#[test]
fn extension_range_measurement_ids_decode() {
    for (lmf, ran) in [(16u16, 256u16), (200, 3)] {
        let (id, _, _) = accepted(&ecid_report(1, lmf, ran, nr_cgi(PLMN, 1), TAC, None));
        assert_eq!(id, u64::from(lmf));
    }
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
    let (id, cells, ei) = accepted(&splice_ie(&report(), 9999, IGNORE));
    assert_eq!((id, cells.len()), (3, 1));
    assert!(ei.is_none());
}

#[test]
fn an_unknown_notify_ie_is_processed_and_reported() {
    let (id, cells, ei) = accepted(&splice_ie(&report(), 9999, NOTIFY));
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
    let outcome = decode_ecid_report(&splice_ie(&report(), 9999, REJECT)).unwrap();
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
}

#[test]
fn a_missing_measurement_id_rejects_the_report_and_is_reported_missing() {
    for id in [
        nrppa::ID_LMF_UE_MEASUREMENT_ID,
        nrppa::ID_RAN_UE_MEASUREMENT_ID,
    ] {
        let EcidReportOutcome::Rejected {
            error_indication, ..
        } = decode_ecid_report(&drop_ie(&report(), id)).unwrap()
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
    let (id, cells, ei) = accepted(&drop_ie(&report(), nrppa::ID_E_CID_MEASUREMENT_RESULT));
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
