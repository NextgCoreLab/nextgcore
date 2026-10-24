//! #807: the gNB half end to end inside the LMF. A fake NG-RAN answers each NRPPa
//! request the way TS 38.455 describes, through the same waiter path the uplink
//! notify uses, and the gNB halves it measures are paired with the UE's LPP halves
//! into a Multi-RTT fix.

use super::*;
use crate::context::{
    lmf_context_init, LegProgress, MeasurementLeg, PositioningMethod, PositioningOutcome,
    PositioningQos, PROCESS_STATE_TEST_LOCK,
};
use crate::nrppa_positioning::test_support as gnb;
use crate::positioning::{
    enu_to_geodetic, geodetic_to_enu, EnuPoint, TrpCoord, SPEED_OF_LIGHT_M_S,
};
use std::sync::Mutex;

const TC_NS: f64 = 1e9 / (480_000.0 * 4_096.0);
const ORIGIN: (f64, f64) = (51.4778, -0.0015);
/// (TRP id, PCI, east, north) on a 1 km square; the UE at (350, 600) m.
const TRPS: [(u16, u16, f64, f64); 4] = [
    (1, 201, 0.0, 0.0),
    (2, 202, 1000.0, 0.0),
    (3, 203, 0.0, 1000.0),
    (4, 204, 1000.0, 1000.0),
];
const UE: (f64, f64) = (350.0, 600.0);
/// The UE clock runs this far ahead of the gNBs'; the UE sends SRS this long
/// after the PRS. Neither half alone is a range (see `tests_multi_rtt_two_sided`).
const UE_CLOCK_OFFSET_NS: f64 = 3_000.0;
const SRS_AFTER_PRS_NS: f64 = 1_000.0;
const SRS_SET: u8 = 5;
/// The TRPs' SFN initialisation time, 32.32 seconds since 1900 (#911).
const SFN_INIT: u64 = 3_900_000_000u64 << 32;

fn node() -> NgRanNode {
    NgRanNode {
        mcc: "001".into(),
        mnc: "01".into(),
        gnb_id: 0x807,
        bit_length: 22,
    }
}

fn origin() -> TrpCoord {
    TrpCoord::new(ORIGIN.0, ORIGIN.1, 0.0)
}

fn coord(e: f64, n: f64) -> TrpCoord {
    enu_to_geodetic(EnuPoint { e, n, u: 0.0 }, origin())
}

fn propagation_ns(e: f64, n: f64) -> f64 {
    (UE.0 - e).hypot(UE.1 - n) / SPEED_OF_LIGHT_M_S * 1e9
}

/// What the fake NG-RAN saw: (procedure code, UE-associated?) per PDU.
#[derive(Default)]
struct FakeNgRan {
    seen: Mutex<Vec<(u8, bool, Vec<u8>)>>,
    /// The gNB measures at SFN 700, slot `gnb_slot` (30 kHz). The UE's LPP
    /// fixture is stamped SFN 700, slot 11.
    gnb_slot: u8,
    /// An extra TRP `(id, pci, east, north)` reported in TRP Information and
    /// measured (#903 review: a PCI shared by two TRPs).
    extra: Option<(u16, u16, f64, f64)>,
    /// Answer the Measurement procedure with MEASUREMENT FAILURE.
    measurement_fails: bool,
    /// Never answer TRP Information Exchange.
    silent_trp_information: bool,
    /// Report each TRP's CGI, ARFCN, PRS configuration and SFN initialisation
    /// time too (#911).
    with_prs: bool,
}

impl FakeNgRan {
    fn trps(&self) -> Vec<(u16, u16, f64, f64)> {
        TRPS.iter().copied().chain(self.extra).collect()
    }
}

impl FakeNgRan {
    fn answer(&self, pdu: &[u8], ue: bool) -> bool {
        let Ok(nrppa::NRPPA_PDU::InitiatingMessage(m)) = nextgcore_nrppa_gen::decode(pdu) else {
            panic!("the LMF sent an undecodable or non-initiating NRPPa PDU");
        };
        let (procedure, txn) = (m.procedure_code.0, m.nrppatransaction_id.0);
        self.seen
            .lock()
            .unwrap()
            .push((procedure, ue, pdu.to_vec()));
        let answer = match m.value {
            nrppa::InitiatingMessageValue::Id_tRPInformationExchange(_) => {
                if self.silent_trp_information {
                    return true;
                }
                let scale = f64::from(1u32 << 31);
                let trps: Vec<_> = self
                    .trps()
                    .iter()
                    .map(|(id, pci, e, n)| {
                        let c = coord(*e, *n);
                        (
                            *id,
                            *pci,
                            (c.lat_deg * scale / 90.0).floor() as i32,
                            (c.lon_deg * scale / 180.0).floor() as i32,
                            0,
                        )
                    })
                    .collect();
                if self.with_prs {
                    use nrppa::TRPInformationTypeResponseItem as I;
                    let items = trps
                        .iter()
                        .map(|&(id, pci, lat, lon, alt)| {
                            (
                                id,
                                vec![
                                    I::PCI_NR(nrppa::TRPInformationTypeResponseItem_pCI_NR(pci)),
                                    I::CGI_NR(gnb::cgi_nr(
                                        [0x00, 0xf1, 0x10],
                                        0x807_000 + u64::from(id),
                                    )),
                                    I::ARFCN(nrppa::TRPInformationTypeResponseItem_aRFCN(620_000)),
                                    I::PRSConfiguration(crate::dl_prs_assistance::tests::config(
                                        vec![crate::dl_prs_assistance::tests::set(
                                            0,
                                            1,
                                            5,
                                            0,
                                            0,
                                            620_000,
                                            &[(100 + id, 0)],
                                        )],
                                    )),
                                    // Synchronised: one SFN initialisation time for all.
                                    I::SFNInitialisationTime(nrppa::RelativeTime1900(
                                        (0..64).map(|i| (SFN_INIT >> (63 - i)) & 1 == 1).collect(),
                                    )),
                                    gnb::geographical(lat, lon, alt),
                                ],
                            )
                        })
                        .collect();
                    gnb::trp_information_response_items(txn, items)
                } else {
                    gnb::trp_information_response(txn, &trps)
                }
            }
            nrppa::InitiatingMessageValue::Id_positioningInformationExchange(_) => {
                gnb::positioning_information_response(txn, gnb::srs_configuration(SRS_SET))
            }
            nrppa::InitiatingMessageValue::Id_positioningActivation(_) => {
                gnb::positioning_activation_response(txn)
            }
            nrppa::InitiatingMessageValue::Id_Measurement(req) => {
                let lmf_id = req
                    .protocol_i_es
                    .0
                    .iter()
                    .find_map(|ie| match &ie.value {
                        nrppa::MeasurementRequestProtocolIEs_EntryValue::Id_LMF_Measurement_ID(
                            id,
                        ) => Some(id.0),
                        _ => None,
                    })
                    .expect("LMF-Measurement-ID");
                if self.measurement_fails {
                    let answer = gnb::measurement_failure(txn, lmf_id);
                    lmf_self()
                        .read()
                        .unwrap()
                        .nrppa_deliver(procedure, txn, None, answer);
                    return true;
                }
                // gNB Rx-Tx_i = (gap - offset) + t_i, as a k1 code:
                // T = (2v - 985024)·T_c.
                let requested: Vec<u16> = req
                    .protocol_i_es
                    .0
                    .iter()
                    .find_map(|ie| match &ie.value {
                        nrppa::MeasurementRequestProtocolIEs_EntryValue::Id_TRP_MeasurementRequestList(l) => {
                            Some(l.0.iter().map(|t| t.trp_id.0).collect())
                        }
                        _ => None,
                    })
                    .unwrap_or_default();
                let results: Vec<_> = self
                    .trps()
                    .into_iter()
                    .filter(|(id, ..)| requested.contains(id))
                    .collect::<Vec<_>>()
                    .iter()
                    .map(|(id, _, e, n)| {
                        let t = propagation_ns(*e, *n) - UE_CLOCK_OFFSET_NS + SRS_AFTER_PRS_NS;
                        (
                            *id,
                            ((t / TC_NS + 985_024.0) / 2.0).round() as u32,
                            700,
                            self.gnb_slot,
                        )
                    })
                    .collect();
                gnb::measurement_response(txn, lmf_id, &results)
            }
            // Positioning Deactivation is class 2: no answer.
            nrppa::InitiatingMessageValue::Id_positioningDeactivation(_) => return true,
            other => panic!("unexpected NRPPa request {other:?}"),
        };
        assert!(
            lmf_self()
                .read()
                .unwrap()
                .nrppa_deliver(procedure, txn, None, answer),
            "nobody waited for the answer to procedure {procedure} transaction {txn}"
        );
        true
    }
}

impl NrppaTransport for FakeNgRan {
    async fn send_ue(&self, pdu: Vec<u8>) -> bool {
        self.answer(&pdu, true)
    }
    async fn send_non_ue(&self, n: &NgRanNode, pdu: Vec<u8>) -> bool {
        assert_eq!(*n, node(), "non-UE NRPPa goes to the configured node");
        self.answer(&pdu, false)
    }
}

/// The UE's LPP halves: UE Rx-Tx_i = (t_i + offset) - gap, as k0 codes.
fn ue_halves() -> Vec<CellMeasurement> {
    ue_halves_of(&TRPS)
}

/// The UE's LPP halves for `trps`, each with its own DL-PRS ID (its TRP id).
fn ue_halves_of(trps: &[(u16, u16, f64, f64)]) -> Vec<CellMeasurement> {
    let cells: Vec<(u8, u16, u32)> = trps
        .iter()
        .map(|(id, pci, e, n)| {
            let t = propagation_ns(*e, *n) + UE_CLOCK_OFFSET_NS - SRS_AFTER_PRS_NS;
            (*id as u8, *pci, (t / TC_NS + 985_024.0).round() as u32)
        })
        .collect();
    crate::codec_glue::decode_lpp_provide_report(&crate::lpp_fixtures::multi_rtt_lpp_with_prs(
        &cells, 7,
    ))
    .expect("decodes")
    .1
}

fn setup() {
    lmf_context_init(64);
    lmf_self().read().unwrap().set_ng_ran_nodes(vec![node()]);
}

fn register() -> (
    u64,
    String,
    tokio::sync::oneshot::Receiver<PositioningOutcome>,
) {
    let ctx = lmf_self();
    let c = ctx.read().unwrap();
    let req = c
        .measurement_request(
            0,
            PositioningMethod::NrBased,
            None,
            None,
            PositioningQos::HighAccuracy,
        )
        .expect("measurement store");
    let (corr, rx) =
        c.positioning_session_register(Some("imsi-001010000000807".into()), 7, req.request_id);
    c.positioning_session_expect_leg(&corr, MeasurementLeg::NrppaTrp);
    (req.request_id, corr, rx)
}

/// The whole gNB half, in TS 38.305 §8.10.3.2 order, and a Multi-RTT fix from
/// both halves. The UE's report comes FIRST and must not end the session.
#[tokio::test]
async fn the_gnb_half_is_measured_and_paired_into_a_multi_rtt_fix() {
    let _g = PROCESS_STATE_TEST_LOCK.lock().await;
    setup();
    let ran = FakeNgRan {
        gnb_slot: 12,
        ..Default::default()
    };
    let prepared = prepare(&ran, Duration::from_secs(1), 1_000, &[])
        .await
        .expect("the gNB half is set up");
    let (request_id, _corr, mut rx) = register();

    let ctx = lmf_self();
    assert!(
        matches!(
            ctx.read().unwrap().measurement_leg_report(
                request_id,
                MeasurementLeg::Lpp,
                ue_halves()
            ),
            LegProgress::Waiting
        ),
        "a UE-only Multi-RTT report must wait for the gNB half, not end the session"
    );
    assert!(rx.try_recv().is_err(), "nothing was solved yet");

    let cells = collect(&ran, prepared, Duration::from_secs(1)).await;
    assert_eq!(cells.len(), 4, "one gNB half per TRP");
    assert!(cells
        .iter()
        .all(|c| c.nr_cgi.starts_with("pci-20") && c.meas_time.is_some()));
    let progress =
        ctx.read()
            .unwrap()
            .measurement_leg_report(request_id, MeasurementLeg::NrppaTrp, cells);
    let LegProgress::Completed(Some(fix)) = progress else {
        panic!("both halves in: the session must be solved, got {progress:?}");
    };
    assert_eq!(fix.method_used.as_deref(), Some("MULTI-RTT"));
    let got = geodetic_to_enu(TrpCoord::new(fix.latitude, fix.longitude, 0.0), origin());
    let err = (got.e - UE.0).hypot(got.n - UE.1);
    assert!(err < 1.0, "the fix is {err:.2} m from the UE");
    assert!(matches!(rx.try_recv(), Ok(PositioningOutcome::Fix(_))));

    // The TRP positions came from NG-RAN: nothing was configured.
    assert!(ctx
        .read()
        .unwrap()
        .build_trp_registry()
        .lookup("pci-204")
        .is_some());

    // The procedures, in order, and over the right association.
    let seen = ran.seen.lock().unwrap();
    let order: Vec<(u8, bool)> = seen.iter().map(|(p, ue, _)| (*p, *ue)).collect();
    assert_eq!(
        order,
        vec![
            (nrppa::ID_T_RP_INFORMATION_EXCHANGE, false),
            (nrppa::ID_POSITIONING_INFORMATION_EXCHANGE, true),
            (nrppa::ID_POSITIONING_ACTIVATION, true),
            (nrppa::ID_MEASUREMENT, false),
            (nrppa::ID_POSITIONING_DEACTIVATION, true),
        ]
    );
    // The Measurement Request carries the UE's SRS configuration and asks for the
    // gNB Rx-Tx time difference of all four TRPs.
    let nrppa::NRPPA_PDU::InitiatingMessage(m) = nextgcore_nrppa_gen::decode(&seen[3].2).unwrap()
    else {
        unreachable!()
    };
    let nrppa::InitiatingMessageValue::Id_Measurement(req) = m.value else {
        unreachable!()
    };
    use nrppa::MeasurementRequestProtocolIEs_EntryValue as V;
    assert!(req.protocol_i_es.0.iter().any(|ie| matches!(&ie.value,
        V::Id_SRSConfiguration(c) if *c == gnb::srs_configuration(SRS_SET))));
    assert!(req.protocol_i_es.0.iter().any(|ie| matches!(&ie.value,
        V::Id_TRP_MeasurementRequestList(l) if l.0.iter().map(|t| t.trp_id.0).collect::<Vec<_>>() == [1, 2, 3, 4])));
    assert!(req.protocol_i_es.0.iter().any(|ie| matches!(&ie.value,
        V::Id_TRPMeasurementQuantities(q) if q.0[0].trp_measurement_type.0 == nrppa::TRPMeasurementType::G_NB_RX_TX_TIME_DIFF)));
    // The activated semi-persistent set is the one deactivated.
    let nrppa::NRPPA_PDU::InitiatingMessage(m) = nextgcore_nrppa_gen::decode(&seen[4].2).unwrap()
    else {
        unreachable!()
    };
    let nrppa::InitiatingMessageValue::Id_positioningDeactivation(d) = m.value else {
        unreachable!()
    };
    assert!(matches!(
        d.protocol_i_es.0[0].value,
        nrppa::PositioningDeactivationProtocolIEs_EntryValue::Id_AbortTransmission(
            nrppa::AbortTransmission::DeactivateSRSResourceSetID(nrppa::SRSResourceSetID(SRS_SET))
        )
    ));
}

/// Halves measured too far apart are not one round trip: no fix, and the session
/// ends as a solver failure rather than with a wrong position.
#[tokio::test]
async fn halves_measured_seconds_apart_are_not_paired() {
    let _g = PROCESS_STATE_TEST_LOCK.lock().await;
    setup();
    // 30 kHz slot 11 vs SFN 700 + 0: the gNB stamp is set to another frame below.
    let ran = FakeNgRan {
        gnb_slot: 11,
        ..Default::default()
    };
    let prepared = prepare(&ran, Duration::from_secs(1), 1_000, &[])
        .await
        .unwrap();
    let (request_id, _corr, _rx) = register();
    let ctx = lmf_self();
    ctx.read()
        .unwrap()
        .measurement_leg_report(request_id, MeasurementLeg::Lpp, ue_halves());
    let mut cells = collect(&ran, prepared, Duration::from_secs(1)).await;
    for c in &mut cells {
        // One second later (100 frames).
        let t = c.meas_time.as_mut().unwrap();
        t.sfn += 100;
    }
    let progress =
        ctx.read()
            .unwrap()
            .measurement_leg_report(request_id, MeasurementLeg::NrppaTrp, cells);
    assert!(
        matches!(progress, LegProgress::Completed(None)),
        "halves 1 s apart must not be ranged, got {progress:?}"
    );
}

/// A serving gNB that configures no SRS cannot give a gNB half: `prepare` says so
/// and the caller asks for DL-TDOA instead. No Measurement Request is sent.
#[tokio::test]
async fn no_srs_configuration_means_no_gnb_half() {
    struct NoSrs(FakeNgRan);
    impl NrppaTransport for NoSrs {
        async fn send_ue(&self, pdu: Vec<u8>) -> bool {
            let Some((_, procedure, txn)) = crate::nrppa_positioning::header(&pdu) else {
                return false;
            };
            if procedure == nrppa::ID_POSITIONING_INFORMATION_EXCHANGE {
                self.0.seen.lock().unwrap().push((procedure, true, pdu));
                let answer = gnb::successful(
                    procedure,
                    txn,
                    nrppa::SuccessfulOutcomeValue::Id_positioningInformationExchange(
                        nrppa::PositioningInformationResponse {
                            protocol_i_es: nrppa::PositioningInformationResponseProtocolIEs(vec![]),
                        },
                    ),
                );
                lmf_self()
                    .read()
                    .unwrap()
                    .nrppa_deliver(procedure, txn, None, answer);
                return true;
            }
            self.0.answer(&pdu, true)
        }
        async fn send_non_ue(&self, n: &NgRanNode, pdu: Vec<u8>) -> bool {
            self.0.send_non_ue(n, pdu).await
        }
    }
    let _g = PROCESS_STATE_TEST_LOCK.lock().await;
    setup();
    let ran = NoSrs(FakeNgRan::default());
    let err = prepare(&ran, Duration::from_secs(1), 1_000, &[])
        .await
        .err()
        .expect("no SRS, no gNB half");
    assert!(err.contains("SRS"), "{err}");
    assert!(
        !ran.0
            .seen
            .lock()
            .unwrap()
            .iter()
            .any(|(p, _, _)| *p == nrppa::ID_MEASUREMENT),
        "no Measurement Request without the SRS to measure"
    );
}

/// The UE's answer to the Multi-RTT + DL-TDOA request: both sets.
fn ue_halves_and_rstds() -> Vec<CellMeasurement> {
    let cells: Vec<(u8, u16, u32)> = TRPS
        .iter()
        .map(|(id, pci, e, n)| {
            let t = propagation_ns(*e, *n) + UE_CLOCK_OFFSET_NS - SRS_AFTER_PRS_NS;
            (*id as u8, *pci, (t / TC_NS + 985_024.0).round() as u32)
        })
        .collect();
    // RSTDs relative to TRP 1 (DL-PRS 0), neighbours by DL-PRS and PCI.
    let d_ref = propagation_ns(TRPS[0].2, TRPS[0].3);
    let neighbours: Vec<(u8, Option<u16>, u32)> = TRPS[1..]
        .iter()
        .enumerate()
        .map(|(i, (_, pci, e, n))| {
            let rstd = propagation_ns(*e, *n) - d_ref;
            (
                (i + 1) as u8,
                Some(*pci),
                (rstd / TC_NS + 985_024.0).round() as u32,
            )
        })
        .collect();
    let bytes = crate::lpp_fixtures::multi_rtt_and_dl_tdoa_lpp(&cells, 0, &neighbours, 7);
    crate::codec_glue::decode_lpp_provide_report(&bytes)
        .expect("decodes")
        .1
}

/// #903 review MAJOR 2: once the Measurement Request has gone out, a gNB that
/// answers MEASUREMENT FAILURE leaves no gNB half. The UE was asked for DL-TDOA
/// too, so the session falls back to a DL-TDOA fix instead of ending in 500.
#[tokio::test]
async fn a_measurement_failure_falls_back_to_the_dl_tdoa_fix() {
    let _g = PROCESS_STATE_TEST_LOCK.lock().await;
    setup();
    let ran = FakeNgRan {
        measurement_fails: true,
        ..Default::default()
    };
    let prepared = prepare(&ran, Duration::from_secs(1), 1_000, &[])
        .await
        .unwrap();
    let (request_id, _corr, mut rx) = register();
    let ctx = lmf_self();
    // DL-TDOA needs the reference TRP, which reports no PCI: key it by DL-PRS ID.
    ctx.read()
        .unwrap()
        .set_cell_coord("prs-0", coord(TRPS[0].2, TRPS[0].3));
    ctx.read().unwrap().measurement_leg_report(
        request_id,
        MeasurementLeg::Lpp,
        ue_halves_and_rstds(),
    );
    let cells = collect(&ran, prepared, Duration::from_secs(1)).await;
    assert!(cells.is_empty(), "MEASUREMENT FAILURE gives no gNB half");
    let progress =
        ctx.read()
            .unwrap()
            .measurement_leg_report(request_id, MeasurementLeg::NrppaTrp, cells);
    let LegProgress::Completed(Some(fix)) = progress else {
        panic!("a DL-TDOA fix, not a failure: {progress:?}");
    };
    assert_eq!(fix.method_used.as_deref(), Some("DL_TDOA"));
    let got = geodetic_to_enu(TrpCoord::new(fix.latitude, fix.longitude, 0.0), origin());
    assert!((got.e - UE.0).hypot(got.n - UE.1) < 1.0);
    assert!(matches!(rx.try_recv(), Ok(PositioningOutcome::Fix(_))));
}

/// #903 review MAJOR 1: two TRPs under one PCI (a multi-TRP cell, or PCI reuse).
/// TRP 5 shares PCI 201 with TRP 1 at another site. Keyed by PCI, the halves of
/// the two were summed and the range came out as (d1 + d5)/2. That PCI is now not
/// measured and its position is not learned; the other three TRPs are measured.
#[tokio::test]
async fn a_pci_on_two_trps_is_not_ranged() {
    let _g = PROCESS_STATE_TEST_LOCK.lock().await;
    setup();
    let ran = FakeNgRan {
        gnb_slot: 12,
        extra: Some((5, 201, 2000.0, 300.0)),
        ..Default::default()
    };
    let prepared = prepare(&ran, Duration::from_secs(1), 1_000, &[])
        .await
        .unwrap();
    // The Measurement Request names neither TRP of PCI 201.
    let seen = ran.seen.lock().unwrap().clone();
    let (_, _, req) = seen
        .iter()
        .find(|(p, ..)| *p == nrppa::ID_MEASUREMENT)
        .unwrap();
    let nrppa::NRPPA_PDU::InitiatingMessage(m) = nextgcore_nrppa_gen::decode(req).unwrap() else {
        unreachable!()
    };
    let nrppa::InitiatingMessageValue::Id_Measurement(r) = m.value else {
        unreachable!()
    };
    assert!(r.protocol_i_es.0.iter().any(|ie| matches!(&ie.value,
        nrppa::MeasurementRequestProtocolIEs_EntryValue::Id_TRP_MeasurementRequestList(l)
            if l.0.iter().map(|t| t.trp_id.0).collect::<Vec<_>>() == [2, 3, 4])));
    assert!(
        lmf_self()
            .read()
            .unwrap()
            .build_trp_registry()
            .lookup("pci-201")
            .is_none(),
        "no coordinate is learned for an ambiguous PCI"
    );
    let (request_id, _corr, _rx) = register();
    let ctx = lmf_self();
    ctx.read().unwrap().measurement_leg_report(
        request_id,
        MeasurementLeg::Lpp,
        // The UE measures TRP 5 too, under the same PCI 201 (its own DL-PRS ID).
        ue_halves_of(&[TRPS[0], TRPS[1], TRPS[2], TRPS[3], (5, 201, 2000.0, 300.0)]),
    );
    let cells = collect(&ran, prepared, Duration::from_secs(1)).await;
    assert_eq!(cells.len(), 3);
    let LegProgress::Completed(Some(fix)) =
        ctx.read()
            .unwrap()
            .measurement_leg_report(request_id, MeasurementLeg::NrppaTrp, cells)
    else {
        panic!("three unambiguous TRPs solve");
    };
    assert_eq!(fix.method_used.as_deref(), Some("MULTI-RTT"));
    let got = geodetic_to_enu(TrpCoord::new(fix.latitude, fix.longitude, 0.0), origin());
    let err = (got.e - UE.0).hypot(got.n - UE.1);
    assert!(
        err < 1.0,
        "the true position from the three unambiguous TRPs: {err:.2} m off"
    );
}

/// #903 review MINOR 1: a node that does not answer TRP Information is not asked
/// again on the next request, so it does not cost every request a timeout.
#[tokio::test]
async fn a_silent_node_is_backed_off() {
    let _g = PROCESS_STATE_TEST_LOCK.lock().await;
    setup();
    let ran = FakeNgRan {
        silent_trp_information: true,
        ..Default::default()
    };
    assert!(prepare(&ran, Duration::from_millis(50), 1_000, &[])
        .await
        .is_err());
    assert!(prepare(&ran, Duration::from_millis(50), 1_000, &[])
        .await
        .is_err());
    let asked = ran
        .seen
        .lock()
        .unwrap()
        .iter()
        .filter(|(p, ..)| *p == nrppa::ID_T_RP_INFORMATION_EXCHANGE)
        .count();
    assert_eq!(
        asked, 1,
        "the second request does not ask the silent node again"
    );
}

/// The UE's Multi-RTT halves for `trps` named by the DL-PRS IDs the assistance
/// data gave them (#911), with the PCI each TRP has.
fn ue_halves_by_assigned_id(
    trps: &[(u16, u16, f64, f64)],
    assistance: &Assistance,
) -> Vec<CellMeasurement> {
    let cells: Vec<(u8, u16, u32)> = trps
        .iter()
        .map(|(id, pci, e, n)| {
            let prs = assistance
                .trps
                .iter()
                .find(|(_, t, _)| t == id)
                .map(|(_, _, p)| *p)
                .expect("the TRP was described");
            let t = propagation_ns(*e, *n) + UE_CLOCK_OFFSET_NS - SRS_AFTER_PRS_NS;
            (prs, *pci, (t / TC_NS + 985_024.0).round() as u32)
        })
        .collect();
    crate::codec_glue::decode_lpp_provide_report(&crate::lpp_fixtures::multi_rtt_lpp_with_prs(
        &cells, 7,
    ))
    .expect("decodes")
    .1
}

/// #911: the assistance data describes every TRP that reported a PRS
/// configuration, each under its own DL-PRS ID, and keys its position by the TRP.
#[tokio::test]
async fn the_assistance_data_names_each_trp_by_its_own_dl_prs_id() {
    let _g = PROCESS_STATE_TEST_LOCK.lock().await;
    setup();
    let ran = FakeNgRan {
        with_prs: true,
        extra: Some((5, 201, 2000.0, 300.0)),
        ..Default::default()
    };
    let a = prepare_assistance(&ran, Duration::from_secs(1), None)
        .await
        .expect("assistance data");
    let ids: Vec<u8> = a.trps.iter().map(|(_, _, id)| *id).collect();
    assert_eq!(
        ids,
        vec![0, 1, 2, 3, 4],
        "one DL-PRS ID per TRP, PCI 201 twice included"
    );
    assert_eq!(a.built.dl_prs_ids, ids);
    for (node, trp, id) in &a.trps {
        let key = crate::context::trp_key(node, *trp);
        assert_eq!(a.keys.get(id), Some(&key));
        assert!(
            lmf_self()
                .read()
                .unwrap()
                .build_trp_registry()
                .lookup(&key)
                .is_some(),
            "{key} has the position NG-RAN reported"
        );
    }
    assert_eq!(crate::context::trp_key(&node(), 5), "trp-00101-807-5");
    // The PRS of TRP 5 is the one TRP 5 reported, with its CGI and ARFCN.
    let per = &a.built.data.nr_dl_prs_assistance_data_list_r16.0[0]
        .nr_dl_prs_assistance_data_per_freq_r16
        .0;
    let t5 = per.iter().find(|t| t.dl_prs_id_r16.0 == 4).unwrap();
    assert_eq!(t5.nr_phys_cell_id_r16.as_ref().map(|p| p.0), Some(201));
    assert_eq!(t5.nr_arfcn_r16.as_ref().map(|a| a.0), Some(620_000));
    assert!(t5.nr_cell_global_id_r16.is_some());
    assert_eq!(
        t5.nr_dl_prs_info_r16.nr_dl_prs_resource_set_list_r16.0[0]
            .dl_prs_resource_list_r16
            .0[0]
            .dl_prs_sequence_id_r16
            .0,
        105
    );
    // The same TRPs keep their IDs on the next session.
    let again = prepare_assistance(&ran, Duration::from_secs(1), None)
        .await
        .unwrap();
    assert_eq!(again.trps, a.trps);
}

/// #911, the payoff: two TRPs that share PCI 201 cannot be told apart by PCI
/// (#903 left both out). Named by the DL-PRS IDs of the assistance data, both
/// are measured, paired and ranged, and the fix uses all five TRPs.
#[tokio::test]
async fn a_shared_pci_is_ranged_once_the_assistance_data_names_its_trps() {
    let _g = PROCESS_STATE_TEST_LOCK.lock().await;
    setup();
    let extra = (5, 201, 2000.0, 300.0);
    let ran = FakeNgRan {
        gnb_slot: 12,
        with_prs: true,
        extra: Some(extra),
        ..Default::default()
    };
    let a = prepare_assistance(&ran, Duration::from_secs(1), None)
        .await
        .unwrap();
    let prepared = prepare(&ran, Duration::from_secs(1), 1_000, &a.trps)
        .await
        .unwrap();
    // Both TRPs of PCI 201 are measured now.
    let seen = ran.seen.lock().unwrap().clone();
    let (_, _, req) = seen
        .iter()
        .find(|(p, ..)| *p == nrppa::ID_MEASUREMENT)
        .unwrap();
    let nrppa::NRPPA_PDU::InitiatingMessage(m) = nextgcore_nrppa_gen::decode(req).unwrap() else {
        unreachable!()
    };
    let nrppa::InitiatingMessageValue::Id_Measurement(r) = m.value else {
        unreachable!()
    };
    assert!(r.protocol_i_es.0.iter().any(|ie| matches!(&ie.value,
        nrppa::MeasurementRequestProtocolIEs_EntryValue::Id_TRP_MeasurementRequestList(l)
            if l.0.iter().map(|t| t.trp_id.0).collect::<Vec<_>>() == [1, 2, 3, 4, 5])));

    let (request_id, corr, _rx) = register();
    let ctx = lmf_self();
    ctx.read()
        .unwrap()
        .positioning_session_set_dl_prs_keys(&corr, a.keys.clone());
    let all = [TRPS[0], TRPS[1], TRPS[2], TRPS[3], extra];
    ctx.read().unwrap().measurement_leg_report(
        request_id,
        MeasurementLeg::Lpp,
        ue_halves_by_assigned_id(&all, &a),
    );
    let cells = collect(&ran, prepared, Duration::from_secs(1)).await;
    assert_eq!(cells.len(), 5, "a gNB half for every TRP");
    assert!(cells.iter().all(|c| c.nr_cgi.starts_with("trp-")));
    let gnb_cells = cells.clone();
    let LegProgress::Completed(Some(fix)) =
        ctx.read()
            .unwrap()
            .measurement_leg_report(request_id, MeasurementLeg::NrppaTrp, cells)
    else {
        panic!("five TRPs solve");
    };
    assert_eq!(fix.method_used.as_deref(), Some("MULTI-RTT"));
    let got = geodetic_to_enu(TrpCoord::new(fix.latitude, fix.longitude, 0.0), origin());
    let err = (got.e - UE.0).hypot(got.n - UE.1);
    assert!(err < 1.0, "{err:.2} m off");
    // The ranges: all five, TRP 5 at its own distance. The UE halves keyed as the
    // session keys them, by the TRP their DL-PRS ID names.
    let registry = ctx.read().unwrap().build_trp_registry();
    let mut both: Vec<CellMeasurement> = ue_halves_by_assigned_id(&all, &a)
        .into_iter()
        .map(|mut c| {
            c.nr_cgi = a.keys[&c.dl_prs_id.unwrap()].clone();
            c
        })
        .collect();
    both.extend(gnb_cells);
    let obs = crate::context::multi_rtt_observations_for_test(&both, &registry);
    assert_eq!(obs.len(), 5);
    let key5 = crate::context::trp_key(&node(), 5);
    let r5 = obs.iter().find(|o| o.trp_id == key5).unwrap().range_m;
    let want = (UE.0 - extra.2).hypot(UE.1 - extra.3);
    assert!(
        (r5 - want).abs() < 1.0,
        "TRP 5 ranged {r5:.1} m, truly {want:.1} m"
    );
}

/// #911: a DL-TDOA report on the assistance data's DL-PRS IDs solves against the
/// TRPs those IDs name. The reference TRP carries no PCI at all.
#[tokio::test]
async fn a_dl_tdoa_report_on_assigned_dl_prs_ids_is_solved() {
    let _g = PROCESS_STATE_TEST_LOCK.lock().await;
    setup();
    let ran = FakeNgRan {
        with_prs: true,
        ..Default::default()
    };
    let a = prepare_assistance(&ran, Duration::from_secs(1), None)
        .await
        .unwrap();
    let id_of = |trp: u16| a.trps.iter().find(|(_, t, _)| *t == trp).unwrap().2;
    let d_ref = propagation_ns(TRPS[0].2, TRPS[0].3);
    let neighbours: Vec<(u8, Option<u16>, u32)> = TRPS[1..]
        .iter()
        .map(|(id, pci, e, n)| {
            let rstd = propagation_ns(*e, *n) - d_ref;
            (
                id_of(*id),
                Some(*pci),
                (rstd / TC_NS + 985_024.0).round() as u32,
            )
        })
        .collect();
    let cells = crate::codec_glue::decode_lpp_provide_report(&crate::lpp_fixtures::dl_tdoa_lpp(
        id_of(1),
        &neighbours,
        7,
    ))
    .unwrap()
    .1;
    let ctx = lmf_self();
    let c = ctx.read().unwrap();
    let req = c
        .measurement_request(
            0,
            PositioningMethod::NrBased,
            None,
            None,
            PositioningQos::HighAccuracy,
        )
        .unwrap();
    let (corr, _rx) = c.positioning_session_register(Some("imsi-911".into()), 8, req.request_id);
    c.positioning_session_set_dl_prs_keys(&corr, a.keys.clone());
    let LegProgress::Completed(Some(fix)) =
        c.measurement_leg_report(req.request_id, MeasurementLeg::Lpp, cells)
    else {
        panic!("a DL-TDOA fix");
    };
    assert_eq!(fix.method_used.as_deref(), Some("DL_TDOA"));
    let got = geodetic_to_enu(TrpCoord::new(fix.latitude, fix.longitude, 0.0), origin());
    assert!((got.e - UE.0).hypot(got.n - UE.1) < 1.0);
}
