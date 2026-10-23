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
                let scale = f64::from(1u32 << 31);
                let trps: Vec<_> = TRPS
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
                gnb::trp_information_response(txn, &trps)
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
                // gNB Rx-Tx_i = (gap - offset) + t_i, as a k1 code:
                // T = (2v - 985024)·T_c.
                let results: Vec<_> = TRPS
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
                .nrppa_deliver(procedure, txn, answer),
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
    let cells: Vec<(u16, u32)> = TRPS
        .iter()
        .map(|(_, pci, e, n)| {
            let t = propagation_ns(*e, *n) + UE_CLOCK_OFFSET_NS - SRS_AFTER_PRS_NS;
            (*pci, (t / TC_NS + 985_024.0).round() as u32)
        })
        .collect();
    crate::codec_glue::decode_lpp_provide_report(&crate::lpp_fixtures::multi_rtt_lpp(&cells, 7))
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
    let prepared = prepare(&ran, Duration::from_secs(1), 1_000)
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
    let prepared = prepare(&ran, Duration::from_secs(1), 1_000).await.unwrap();
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
                    .nrppa_deliver(procedure, txn, answer);
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
    let err = prepare(&ran, Duration::from_secs(1), 1_000)
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
