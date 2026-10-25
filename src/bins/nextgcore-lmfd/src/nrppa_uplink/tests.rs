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
        (cells[0].rsrq, cells[0].ecid_rtt_ns, cells[0].aoa),
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

    // #832: TADV is decoded per TS 36.133 §10.3.1 into a round trip (bin
    // midpoint): 2 T_s bins up to 4096 T_s, 8 T_s above, and the last value open.
    let ts = crate::positioning::TS_NS;
    let c = cell(nr_cgi(PLMN, 1), Some(vec![ta1(0)]));
    assert_eq!((c.timing_advance, c.ecid_rtt_ns), (None, Some(ts)));
    let c = cell(nr_cgi(PLMN, 1), Some(vec![ta2(2047)]));
    assert_eq!(c.ecid_rtt_ns, Some(4095.0 * ts));
    let c = cell(nr_cgi(PLMN, 1), Some(vec![ta2(2048)]));
    assert_eq!(c.ecid_rtt_ns, Some(4100.0 * ts));
    let c = cell(nr_cgi(PLMN, 1), Some(vec![ta1(7689)]));
    assert_eq!(c.ecid_rtt_ns, Some((4096.0 + 8.0 * 5641.0 + 4.0) * ts));
    let c = cell(nr_cgi(PLMN, 1), Some(vec![ta2(7690)]));
    assert_eq!(c.ecid_rtt_ns, None, "TADV_7690 is open-ended");
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
        (c.ecid_rtt_ns, c.aoa, c.rsrp, c.rsrq),
        (
            Some(1001.0 * crate::positioning::TS_NS),
            Some(90.0),
            Some(-80),
            Some(10)
        )
    );
}

/// #859: the E-CID report of [`ECID_REPORT`] with its one Measured Results entry
/// replaced by `measured` (the hand-derived octets from SIZE(1..64) on), and the two
/// open-type lengths adjusted.
fn ecid_report_with_measured(measured: &[u8]) -> Vec<u8> {
    let mut out = ECID_REPORT[..36].to_vec();
    out.extend_from_slice(measured);
    let delta = measured.len() as isize - 9;
    out[5] = (0x27 + delta) as u8; // initiatingMessage value length
    out[22] = (0x16 + delta) as u8; // E-CID-MeasurementResult open type length
    out
}

/// #859: the NR Measured Results extensions, from hand-derived X.691 octets (TS
/// 38.455 §9.2.5, choice-Extension of `MeasuredResultsValue`). The generated encoder
/// must produce exactly these, and the decoder must give back the report values.
///
/// ```text
/// 02 80        SIZE(1..64) 0 (6 bits); CHOICE choice-Extension 5 of 6 (3 bits);
///              pad (the IE id is 2-octet aligned)
/// 00 5e        id-NR-TADV (94)
/// 40           criticality ignore (2 bits), pad (aligned open-type length)
/// 02 04 d2     length 2; NR-TADV 1234: INTEGER (0..7690), 2-octet aligned
///
/// 00 76 40 02 f0 7d          id-UE-Rx-Tx-Time-Diff (118); 61565, the top of 0..61565
///
/// 00 20 40 09                id-ResultSS-RSRP (32), ignore, length 9:
///  02 00     SIZE(1..9) 0 (4 bits); item ext 0, opts 0 1 0 0 (valueSS-RSRP-Cell);
///            pad (nR-PCI 0..1007 is 2-octet aligned)
///  00 07     nR-PCI 7
///  80        nR-ARFCN 0..3279165: octet count - 1 = 2 (2 bits), pad
///  09 75 e0  620000
///  a0        valueSS-RSRP-Cell 80 in 7 bits, pad
/// ```
#[test]
fn nr_measured_results_decode_from_hand_derived_octets() {
    let cases: [(&[u8], crate::nrppa_uplink::NrEcidReport); 3] = [
        (
            &[0x02, 0x80, 0x00, 0x5e, 0x40, 0x02, 0x04, 0xd2],
            NrEcidReport {
                nr_tadv: Some(1234),
                ..NrEcidReport::default()
            },
        ),
        (
            &[0x02, 0x80, 0x00, 0x76, 0x40, 0x02, 0xf0, 0x7d],
            NrEcidReport {
                ue_rx_tx_time_diff: Some(61565),
                ..NrEcidReport::default()
            },
        ),
        (
            &[
                0x02, 0x80, 0x00, 0x20, 0x40, 0x09, 0x02, 0x00, 0x00, 0x07, 0x80, 0x09, 0x75, 0xe0,
                0xa0,
            ],
            NrEcidReport {
                ss_rsrp: vec![NrCellResult {
                    pci: 7,
                    arfcn: 620_000,
                    value: Some(80),
                }],
                ..NrEcidReport::default()
            },
        ),
    ];
    let built = [
        nr_tadv(1234),
        ue_rx_tx(61565),
        ss_rsrp(&[(7, 620_000, Some(80))]),
    ];
    for ((octets, want), value) in cases.iter().zip(built) {
        let hand = ecid_report_with_measured(octets);
        assert_eq!(
            ecid_report(9, 3, 5, nr_cgi(PLMN, 1), TAC, Some(vec![value])),
            hand,
            "the generated encoder agrees with the hand-derived octets for {want:?}"
        );
        let (_, cells, ei) = accepted(&hand);
        assert!(ei.is_none());
        assert_eq!(cells[0].nr_ecid.as_ref(), Some(want));
        assert_eq!(
            cells[0].ecid_rtt_ns, None,
            "no timing term: the NR-TADV mapping (TS 38.133) is not implemented"
        );
    }
}

/// #859: every NR quantity in one report is kept, the first of each wins, and a
/// report with only E-UTRA arms carries no NR part.
#[test]
fn every_nr_measured_result_is_kept_as_reported() {
    let cell = |measured| {
        let (_, cells, _) = accepted(&ecid_report(1, 15, 7, nr_cgi(PLMN, 1), TAC, Some(measured)));
        cells.into_iter().next().expect("one serving-cell entry")
    };
    let c = cell(vec![
        nr_tadv(0),
        nr_tadv(7690),
        ue_rx_tx(0),
        ss_rsrp(&[(0, 0, Some(0)), (1007, 3_279_165, Some(127))]),
        ss_rsrq(&[(5, 1000, None)]),
        csi_rsrp(&[(6, 2000, Some(64))]),
        csi_rsrq(&[(7, 3000, Some(1))]),
        // Repeated lists: the first of each is kept (#1134 review).
        ss_rsrp(&[(9, 9, Some(9))]),
        ss_rsrq(&[(9, 9, Some(9))]),
        csi_rsrp(&[(9, 9, Some(9))]),
        csi_rsrq(&[(9, 9, Some(9))]),
        ue_rx_tx(9),
        aoa_nr(3599, Some(1799)),
        aoa_nr(1, None),
        rsrp(&[60]),
    ]);
    assert_eq!(
        c.nr_ecid,
        Some(NrEcidReport {
            nr_tadv: Some(0),
            ue_rx_tx_time_diff: Some(0),
            ss_rsrp: vec![
                NrCellResult {
                    pci: 0,
                    arfcn: 0,
                    value: Some(0)
                },
                NrCellResult {
                    pci: 1007,
                    arfcn: 3_279_165,
                    value: Some(127)
                },
            ],
            ss_rsrq: vec![NrCellResult {
                pci: 5,
                arfcn: 1000,
                value: None
            }],
            csi_rsrp: vec![NrCellResult {
                pci: 6,
                arfcn: 2000,
                value: Some(64)
            }],
            csi_rsrq: vec![NrCellResult {
                pci: 7,
                arfcn: 3000,
                value: Some(1)
            }],
            aoa_nr: Some((3599, Some(1799))),
        })
    );
    assert_eq!(c.rsrp, Some(-80), "the E-UTRA arm is still read");
    assert_eq!(
        (c.ecid_rtt_ns, c.aoa),
        (None, None),
        "no NR value is mapped"
    );
    assert_eq!(cell(vec![rsrp(&[60]), ta1(10)]).nr_ecid, None);
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

/// #834 review: an on-demand E-CID request is answered in the E-CID MEASUREMENT
/// INITIATION RESPONSE (TS 38.455 §8.2.1.2), which a real gNB (and nextgsim) sends.
/// It is read exactly like the report it replaces.
#[test]
fn the_initiation_response_carries_the_results_of_an_on_demand_request() {
    let measured = Some(vec![rsrp(&[60]), ta1(500)]);
    let from_response = accepted(&ecid_initiation_response(
        9,
        3,
        5,
        nr_cgi(PLMN, 1),
        TAC,
        measured.clone(),
    ));
    let from_report = accepted(&ecid_report(9, 3, 5, nr_cgi(PLMN, 1), TAC, measured));
    assert_eq!(from_response.0, 3, "LMF-UE-Measurement-ID");
    assert_eq!(from_response.1.len(), 1);
    assert_eq!(from_response.1[0].nr_cgi, from_report.1[0].nr_cgi);
    assert_eq!(from_response.1[0].rsrp, from_report.1[0].rsrp);
    assert_eq!(from_response.1[0].ecid_rtt_ns, from_report.1[0].ecid_rtt_ns);
    assert!(from_response.1[0].ecid_rtt_ns.is_some());
}

/// The response's error handling names the procedure it belongs to: an unknown
/// reject IE in an E-CID Measurement Initiation Response is reported against
/// procedure 2, successful outcome.
#[test]
fn a_rejected_initiation_response_is_diagnosed_against_procedure_2() {
    let bytes = splice_ie(
        &ecid_initiation_response(9, 3, 5, nr_cgi(PLMN, 1), TAC, None),
        9999,
        0,
    );
    let EcidReportOutcome::Rejected {
        error_indication, ..
    } = decode_ecid_report(&bytes).expect("decodes")
    else {
        panic!("an unknown reject IE rejects the response");
    };
    let nrppa::NRPPA_PDU::InitiatingMessage(m) =
        nextgcore_nrppa_gen::decode(&error_indication).unwrap()
    else {
        panic!("an ERROR INDICATION is an initiating message");
    };
    let nrppa::InitiatingMessageValue::Id_errorIndication(ei) = m.value else {
        panic!("not an ERROR INDICATION");
    };
    let diag = ei
        .protocol_i_es
        .0
        .iter()
        .find_map(|ie| match &ie.value {
            nrppa::ErrorIndicationProtocolIEs_EntryValue::Id_CriticalityDiagnostics(d) => {
                Some(d.clone())
            }
            _ => None,
        })
        .expect("criticality diagnostics");
    assert_eq!(
        diag.procedure_code.map(|p| p.0),
        Some(nrppa::ID_E_CID_MEASUREMENT_INITIATION)
    );
    assert_eq!(
        diag.triggering_message.map(|t| t.0),
        Some(nrppa::TriggeringMessage::SUCCESSFUL_OUTCOME)
    );
}
