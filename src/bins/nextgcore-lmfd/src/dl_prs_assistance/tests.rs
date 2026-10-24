//! #911: DL-PRS assistance data, hand-checked against the TS 37.355 ASN.1.

use super::*;
use nrppa::*;

/// A PRS resource set: `scs` (0..3), periodicity index `period` (NRPPa
/// enumeration), offset, comb index, one resource per `(sequence ID, RE offset)`.
pub(crate) fn set(
    id: u8,
    scs: u8,
    period: u8,
    offset: u32,
    comb: u8,
    point_a: u32,
    resources: &[(u16, u8)],
) -> PRSResourceSet_Item {
    PRSResourceSet_Item {
        prs_resource_set_id: PRS_Resource_Set_ID(id),
        subcarrier_spacing: PRSResourceSet_ItemSubcarrierSpacing(scs),
        pr_sbandwidth: PRSResourceSet_ItemPRSbandwidth(1),
        start_prb: PRSResourceSet_ItemStartPRB(0),
        point_a: PRSResourceSet_ItemPointA(point_a),
        comb_size: PRSResourceSet_ItemCombSize(comb),
        cp_type: PRSResourceSet_ItemCPType(PRSResourceSet_ItemCPType::NORMAL),
        resource_set_periodicity: PRSResourceSet_ItemResourceSetPeriodicity(period),
        resource_set_slot_offset: PRSResourceSet_ItemResourceSetSlotOffset(offset),
        resource_repetition_factor: PRSResourceSet_ItemResourceRepetitionFactor(
            PRSResourceSet_ItemResourceRepetitionFactor::RF1,
        ),
        resource_time_gap: PRSResourceSet_ItemResourceTimeGap(
            PRSResourceSet_ItemResourceTimeGap::TG1,
        ),
        resource_numberof_symbols: PRSResourceSet_ItemResourceNumberofSymbols(
            PRSResourceSet_ItemResourceNumberofSymbols::N2,
        ),
        prs_muting: None,
        prs_resource_transmit_power: PRSResourceSet_ItemPRSResourceTransmitPower(0),
        prs_resource_list: PRSResource_List(
            resources
                .iter()
                .enumerate()
                .map(|(i, (seq, re))| PRSResource_Item {
                    prs_resource_id: PRS_Resource_ID(i as u8),
                    sequence_id: PRSResource_ItemSequenceID(*seq),
                    re_offset: PRSResource_ItemREOffset(*re),
                    resource_slot_offset: PRSResource_ItemResourceSlotOffset(0),
                    resource_symbol_offset: PRSResource_ItemResourceSymbolOffset(0),
                    qcl_info: None,
                    ie_extensions: None,
                })
                .collect(),
        ),
        ie_extensions: None,
    }
}

pub(crate) fn config(sets: Vec<PRSResourceSet_Item>) -> PRSConfiguration {
    PRSConfiguration {
        prs_resource_set_list: PRSResourceSet_List(sets),
        ie_extensions: None,
    }
}

/// SCS 30 kHz, n20 (index 5), offset 0, comb 2, Point A 620000, one resource.
fn simple(seq: u16) -> PRSConfiguration {
    config(vec![set(0, 1, 5, 0, 0, 620_000, &[(seq, 0)])])
}

fn trp(dl_prs_id: u8, pci: u16, prs: PRSConfiguration) -> TrpPrs {
    TrpPrs {
        dl_prs_id,
        pci: Some(pci),
        ncgi: None,
        arfcn: None,
        coord: None,
        sfn_init: None,
        prs,
    }
}

/// The ProvideAssistanceData for two TRPs on one layer, derived by hand from
/// X.691 (UPER) and the TS 37.355 V19.3.0 ASN.1 (`NR-DL-PRS-AssistanceData-r16`,
/// `NR-DL-TDOA-ProvideAssistanceData-r16`). TRP A (DL-PRS ID 0, PCI 1) is the
/// reference. TRP B (DL-PRS ID 1, PCI 2) has no geometry, so its expected RSTD is
/// 0 with the widest window, 246. Each has one resource set: 30 kHz, Point A
/// 620000, comb 2, periodicity 20 slots at offset 0, one resource with sequence
/// ID 5 (A) or 6 (B).
///
/// | bits | field |
/// |------|-------|
/// | `1001` | LPP-Message bitmap: transactionID, ¬sequenceNumber, ¬acknowledgement, lpp-MessageBody |
/// | `00000000000` | transactionID: ext; initiator ext, locationServer; transactionNumber 0 |
/// | `1` | endTransaction TRUE (§5.2.2 step 1) |
/// | `00011` | lpp-MessageBody c1; index 3 provideAssistanceData |
/// | `000` | criticalExtensions c1; provideAssistanceData-r9 |
/// | `10000` | r9-IEs ext bit (additions present); root bitmap: none |
/// | `00000110100` | additions bitmap length 4−1 (groups r14, r16, r18, r19); only the r16 group |
/// | `00101100` | open type length: 44 octets |
/// | `001` | r16 group bitmap: ¬nr-Multi-RTT, ¬nr-DL-AoD, nr-DL-TDOA |
/// | `01000` | NR-DL-TDOA-ProvideAssistanceData: ext; bitmap: nr-DL-PRS-AssistanceData only |
/// | `00` | NR-DL-PRS-AssistanceData: ext; ¬nr-SSB-Config |
/// | `0000000000` | nr-DL-PRS-ReferenceInfo (not extensible): no resource lists; dl-PRS-ID 0 |
/// | `00` | nr-DL-PRS-AssistanceDataList SIZE(1..4): 1 layer |
/// | `0` | NR-DL-PRS-AssistanceDataPerFreq: ext |
/// | `0001000000000000000000001001011101011110000000000` | layer: ext; SCS ext, kHz30; bandwidth 1 (6 bits); startPRB 0 (12 bits); pointA 620000 (22 bits); comb ext, n2; CP ext, normal |
/// | `000001` | nr-DL-PRS-AssistanceDataPerFreq SIZE(1..64): 2 TRPs |
/// | `0100000000000000000001` | TRP A (reference): ext; bitmap: nr-PhysCellID only; dl-PRS-ID 0; PCI 1 (10 bits) |
/// | `000000000000000` | nr-DL-PRS-SFN0-Offset: ext; sfn-Offset 0; integerSubframeOffset 0 |
/// | `011110000000100000000` | nr-DL-PRS-ExpectedRSTD 0 (13 bits, +3841); uncertainty 0 (8 bits) |
/// | `00` | NR-DL-PRS-Info: ext; resource set list SIZE(1..2): 1 |
/// | `00000000` | NR-DL-PRS-ResourceSet: ext; bitmap: no repetition, time gap, muting; set ID 0 |
/// | `00100001100000` | periodicity CHOICE: ext, scs30; inner CHOICE: ext, n20 (index 3 of 17, 5 bits); offset 0 (5 bits) |
/// | `0000111100000000` | numSymbols ext, n2; power 0 (7 bits, +60); resource list SIZE(1..64): 1 |
/// | `00000000000000000101` | NR-DL-PRS-Resource: ext; ¬QCL; resource ID 0; sequence ID 5 (12 bits) |
/// | `00000000000000000` | comb CHOICE: ext, n2; RE offset 0 (1 bit); slot offset 0 (9 bits); symbol offset 0 (4 bits) |
/// | `0100000000010000000010` | TRP B: ext; bitmap: nr-PhysCellID only; dl-PRS-ID 1; PCI 2 (10 bits) |
/// | `000000000000000` | nr-DL-PRS-SFN0-Offset: ext; sfn-Offset 0; integerSubframeOffset 0 |
/// | `011110000000111110110` | nr-DL-PRS-ExpectedRSTD 0 (13 bits, +3841); uncertainty 246 (8 bits) |
/// | `00` | NR-DL-PRS-Info: ext; resource set list SIZE(1..2): 1 |
/// | `00000000` | NR-DL-PRS-ResourceSet: ext; bitmap: no repetition, time gap, muting; set ID 0 |
/// | `00100001100000` | periodicity CHOICE: ext, scs30; inner CHOICE: ext, n20 (index 3 of 17, 5 bits); offset 0 (5 bits) |
/// | `0000111100000000` | numSymbols ext, n2; power 0 (7 bits, +60); resource list SIZE(1..64): 1 |
/// | `00000000000000000110` | NR-DL-PRS-Resource: ext; ¬QCL; resource ID 0; sequence ID 6 (12 bits) |
/// | `00000000000000000` | comb CHOICE: ext, n2; RE offset 0 (1 bit); slot offset 0 (9 bits); symbol offset 0 (4 bits) |
/// | `0000` | open-type padding (4 bits) |
#[test]
fn provide_assistance_data_matches_x691() {
    let built = build(&[trp(0, 1, simple(5)), trp(1, 2, simple(6))], 0, None).unwrap();
    assert_eq!(built.reference, 0);
    assert_eq!(built.dl_prs_ids, vec![0, 1]);
    let bytes = provide_assistance_data(0, &built.data, false, true).unwrap();
    assert_eq!(
        bytes,
        vec![
            0x90, 0x01, 0x18, 0x80, 0x34, 0x2C, 0x28, 0x00, 0x00, 0x20, 0x00, 0x01, 0x2E, 0xBC,
            0x00, 0x05, 0x00, 0x00, 0x10, 0x00, 0x0F, 0x01, 0x00, 0x00, 0x08, 0x60, 0x0F, 0x00,
            0x00, 0x00, 0x50, 0x00, 0x02, 0x00, 0x80, 0x40, 0x00, 0x1E, 0x03, 0xEC, 0x00, 0x10,
            0xC0, 0x1E, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00
        ]
    );
}

/// A Multi-RTT session gets the same assistance data in both bodies, and it
/// decodes back to what was built.
#[test]
fn multi_rtt_and_dl_tdoa_carry_the_same_assistance_data() {
    let built = build(&[trp(0, 1, simple(5)), trp(1, 2, simple(6))], 0, None).unwrap();
    let bytes = provide_assistance_data(9, &built.data, true, true).unwrap();
    let msg = nextgcore_lpp_gen::decode(&bytes).unwrap();
    assert!(
        msg.end_transaction.0,
        "§5.2.2: a single message ends the transaction"
    );
    let Some(lpp::LPP_MessageBody::C1(lpp::LPP_MessageBody_c1::ProvideAssistanceData(p))) =
        msg.lpp_message_body
    else {
        panic!("not ProvideAssistanceData");
    };
    let lpp::ProvideAssistanceDataCriticalExtensions::C1(
        lpp::ProvideAssistanceDataCriticalExtensions_c1::ProvideAssistanceData_r9(ies),
    ) = p.critical_extensions
    else {
        panic!("r9");
    };
    let rtt = ies
        .extensions
        .nr_multi_rtt_provide_assistance_data_r16
        .unwrap();
    let tdoa = ies
        .extensions
        .nr_dl_tdoa_provide_assistance_data_r16
        .unwrap();
    assert_eq!(
        rtt.nr_dl_prs_assistance_data_r16.as_ref(),
        Some(&built.data)
    );
    assert_eq!(
        tdoa.nr_dl_prs_assistance_data_r16.as_ref(),
        Some(&built.data)
    );
}

fn the_sets(b: &Built) -> Vec<(u8, Vec<lpp::NR_DL_PRS_ResourceSet_r16>)> {
    b.data
        .nr_dl_prs_assistance_data_list_r16
        .0
        .iter()
        .flat_map(|l| l.nr_dl_prs_assistance_data_per_freq_r16.0.iter())
        .map(|t| {
            (
                t.dl_prs_id_r16.0,
                t.nr_dl_prs_info_r16
                    .nr_dl_prs_resource_set_list_r16
                    .0
                    .clone(),
            )
        })
        .collect()
}

/// TS 37.355 allows each periodicity only for some subcarrier spacings: 4 slots
/// is a 15 kHz value, so a 30 kHz set with it cannot be described, and neither
/// can an offset not below the periodicity. Such a set is left out, not
/// approximated.
#[test]
fn a_periodicity_lpp_lacks_for_the_spacing_drops_the_set() {
    let ok = |scs, period, offset| {
        build(
            &[trp(
                0,
                1,
                config(vec![set(0, scs, period, offset, 0, 620_000, &[(1, 0)])]),
            )],
            0,
            None,
        )
        .is_ok()
    };
    assert!(ok(0, 0, 3), "15 kHz, 4 slots, offset 3");
    assert!(!ok(1, 0, 0), "30 kHz has no 4-slot periodicity");
    assert!(!ok(0, 0, 4), "offset 4 is not below 4");
    assert!(
        ok(3, 22, 511),
        "120 kHz, 512 slots (an NRPPa extension value)"
    );
    assert!(!ok(0, 22, 0), "15 kHz has no 512-slot periodicity");
}

/// The RE offset must be below the comb size, and maps to the comb's arm.
#[test]
fn the_re_offset_goes_to_the_arm_of_the_layers_comb() {
    use lpp::NR_DL_PRS_Resource_r16Dl_PRS_CombSizeN_AndReOffset_r16 as C;
    let b = build(
        &[trp(
            0,
            1,
            config(vec![set(0, 1, 5, 0, 1, 620_000, &[(1, 3)])]),
        )],
        0,
        None,
    )
    .unwrap();
    let sets = the_sets(&b);
    assert!(matches!(
        sets[0].1[0].dl_prs_resource_list_r16.0[0].dl_prs_comb_size_n_and_re_offset_r16,
        C::N4_r16(lpp::NR_DL_PRS_Resource_r16Dl_PRS_CombSizeN_AndReOffset_r16_n4_r16(3))
    ));
    assert!(build(
        &[trp(
            0,
            1,
            config(vec![set(0, 1, 5, 0, 1, 620_000, &[(1, 4)])])
        )],
        0,
        None
    )
    .is_err());
}

/// rf1 is left out with its time gap; rf4/tg8 map to n4/s8; muting maps.
#[test]
fn repetition_time_gap_and_muting_map_one_to_one() {
    let mut s = set(0, 1, 5, 0, 0, 620_000, &[(1, 0)]);
    s.resource_repetition_factor = PRSResourceSet_ItemResourceRepetitionFactor(
        PRSResourceSet_ItemResourceRepetitionFactor::RF4,
    );
    s.resource_time_gap =
        PRSResourceSet_ItemResourceTimeGap(PRSResourceSet_ItemResourceTimeGap::TG8);
    s.prs_muting = Some(PRSMuting {
        prs_muting_option1: Some(PRSMutingOption1 {
            muting_pattern: DL_PRSMutingPattern::Four(DL_PRSMutingPattern_four(
                [true, false, true, true].into_iter().collect(),
            )),
            muting_bit_repetition_factor: PRSMutingOption1MutingBitRepetitionFactor(
                PRSMutingOption1MutingBitRepetitionFactor::N2,
            ),
            ie_extensions: None,
        }),
        prs_muting_option2: None,
        ie_extensions: None,
    });
    let b = build(&[trp(0, 1, config(vec![s]))], 0, None).unwrap();
    let got = &the_sets(&b)[0].1[0];
    assert_eq!(
        got.dl_prs_resource_repetition_factor_r16
            .as_ref()
            .map(|r| r.0),
        Some(lpp::NR_DL_PRS_ResourceSet_r16Dl_PRS_ResourceRepetitionFactor_r16::N4)
    );
    assert_eq!(
        got.dl_prs_resource_time_gap_r16.as_ref().map(|t| t.0),
        Some(lpp::NR_DL_PRS_ResourceSet_r16Dl_PRS_ResourceTimeGap_r16::S8)
    );
    let m = got.dl_prs_muting_option1_r16.as_ref().unwrap();
    assert_eq!(
        m.dl_prs_muting_bit_repetition_factor_r16
            .as_ref()
            .map(|r| r.0),
        Some(lpp::DL_PRS_MutingOption1_r16Dl_prs_MutingBitRepetitionFactor_r16::N2)
    );
    let lpp::NR_MutingPattern_r16::Po4_r16(p) = &m.nr_option1_muting_r16 else {
        panic!("po4");
    };
    assert_eq!(
        p.0.iter().map(|b| *b).collect::<Vec<_>>(),
        vec![true, false, true, true]
    );

    let plain = build(&[trp(0, 1, simple(1))], 0, None).unwrap();
    let got = &the_sets(&plain)[0].1[0];
    assert!(got.dl_prs_resource_repetition_factor_r16.is_none());
    assert!(got.dl_prs_resource_time_gap_r16.is_none(), "Cond Rep");
}

/// QCL from an SSB gets type C in FR1 and C+D in FR2; without an SSB index it
/// cannot be described and is left out.
#[test]
fn ssb_qcl_type_follows_the_frequency_range() {
    let with_qcl = |point_a: u32, ssb: Option<u8>| {
        let mut s = set(0, 3, 9, 0, 0, point_a, &[(1, 0)]);
        s.prs_resource_list.0[0].qcl_info = Some(PRSResource_QCLInfo::QCLSourceSSB(
            PRSResource_QCLSourceSSB {
                pci_nr: PRSResource_QCLSourceSSBPCI_NR(7),
                ssb_index: ssb.map(SSB_Index),
                ie_extensions: None,
            },
        ));
        let b = build(&[trp(0, 1, config(vec![s]))], 0, None).unwrap();
        the_sets(&b)[0].1[0].dl_prs_resource_list_r16.0[0]
            .dl_prs_qcl_info_r16
            .clone()
    };
    use lpp::DL_PRS_QCL_Info_r16_ssb_r16Rs_Type_r16 as T;
    let rs = |q: Option<lpp::DL_PRS_QCL_Info_r16>| match q {
        Some(lpp::DL_PRS_QCL_Info_r16::Ssb_r16(s)) => {
            Some((s.pci_r16.0, s.ssb_index_r16.0, s.rs_type_r16.0))
        }
        _ => None,
    };
    assert_eq!(rs(with_qcl(620_000, Some(2))), Some((7, 2, T::TYPE_C)));
    assert_eq!(
        rs(with_qcl(2_016_667, Some(2))),
        Some((7, 2, T::TYPE_C_PLUS_TYPE_D))
    );
    assert_eq!(with_qcl(620_000, None), None);
}

/// Sets on different layer parameters go to different layers; a TRP has at
/// most two sets per layer.
#[test]
fn resource_sets_are_grouped_into_layers() {
    let b = build(
        &[
            trp(
                0,
                1,
                config(vec![
                    set(0, 1, 5, 0, 0, 620_000, &[(1, 0)]),
                    set(1, 1, 5, 1, 0, 620_000, &[(2, 0)]),
                    set(2, 1, 5, 2, 0, 620_000, &[(3, 0)]),
                    set(3, 1, 5, 0, 0, 640_000, &[(4, 0)]),
                ]),
            ),
            trp(1, 2, config(vec![set(0, 1, 5, 0, 0, 640_000, &[(5, 0)])])),
        ],
        0,
        None,
    )
    .unwrap();
    let layers = &b.data.nr_dl_prs_assistance_data_list_r16.0;
    assert_eq!(layers.len(), 2);
    assert_eq!(
        layers[0]
            .nr_dl_prs_positioning_frequency_layer_r16
            .dl_prs_point_a_r16
            .0,
        620_000
    );
    let first = &layers[0].nr_dl_prs_assistance_data_per_freq_r16.0;
    assert_eq!(first.len(), 1);
    assert_eq!(
        first[0]
            .nr_dl_prs_info_r16
            .nr_dl_prs_resource_set_list_r16
            .0
            .len(),
        2,
        "nrMaxSetsPerTrpPerFreqLayer-r16"
    );
    let second = &layers[1].nr_dl_prs_assistance_data_per_freq_r16.0;
    assert_eq!(
        second.iter().map(|t| t.dl_prs_id_r16.0).collect::<Vec<_>>(),
        vec![0, 1]
    );
}

/// A reference TRP that cannot be described gives way to the first that can.
#[test]
fn an_undescribable_reference_gives_way() {
    let bad = config(vec![set(0, 1, 0, 0, 0, 620_000, &[(1, 0)])]);
    let b = build(&[trp(4, 1, bad), trp(5, 2, simple(2))], 0, None).unwrap();
    assert_eq!(b.reference, 5);
    assert_eq!(b.dl_prs_ids, vec![5]);
    assert!(build(
        &[trp(4, 1, config(vec![set(0, 1, 0, 0, 0, 1, &[(1, 0)])]))],
        0,
        None
    )
    .is_err());
}

/// 32.32 seconds since 1900: 3 900 000 000 s (in 2023) plus `offset_s`, which
/// may be negative. Exact in the integer part, as the IE is.
fn t1900(offset_s: f64) -> u64 {
    let units = (offset_s * 4_294_967_296.0).round() as i64;
    ((3_900_000_000u64 << 32) as i64 + units) as u64
}

/// Frames, then subframes, from the reference's SFN 0 to this TRP's, across the
/// 10.24 s cycle, with the remainder within ±0.5 ms.
#[test]
fn the_sfn0_offset_counts_frames_then_subframes() {
    let (sfn, sf, rest) = sfn0_offset(Some(t1900(0.0)), Some(t1900(1.2343))).unwrap();
    assert_eq!((sfn, sf), (123, 4));
    assert!((rest - 0.3e-3).abs() < 1e-9, "{rest}");
    // 0.7 ms past a subframe is 0.3 ms before the next one.
    let (sfn, sf, rest) = sfn0_offset(Some(t1900(0.0)), Some(t1900(1.2347))).unwrap();
    assert_eq!((sfn, sf), (123, 5));
    assert!((rest + 0.3e-3).abs() < 1e-9, "{rest}");
    // This TRP's SFN 0 is 1 ms BEFORE the reference's: its next one is 10.239 s on.
    let (sfn, sf, rest) = sfn0_offset(Some(t1900(0.0)), Some(t1900(-0.001))).unwrap();
    assert_eq!((sfn, sf), (1023, 9));
    assert!(rest.abs() < 1e-9);
    // A hair before is synchronised, not 1 ms off; so are whole cycles apart.
    let (sfn, sf, rest) = sfn0_offset(Some(t1900(0.0)), Some(t1900(-1e-9))).unwrap();
    assert_eq!((sfn, sf), (0, 0));
    assert!((rest + 1e-9).abs() < 1e-10, "{rest}"); // 2^-32 s steps
    assert_eq!(
        sfn0_offset(Some(t1900(0.0)), Some(t1900(20.48))).map(|(a, b, _)| (a, b)),
        Some((0, 0))
    );
    assert_eq!(sfn0_offset(None, Some(1)), None);
}

/// The expected RSTD is the propagation difference from the a-priori position
/// in 4·T_s; the window is min(2r, baseline) in 4·T_s (FR1), plus one step.
#[test]
fn the_expected_rstd_follows_the_geometry() {
    use crate::positioning::enu_to_geodetic;
    use crate::positioning::EnuPoint;
    let origin = TrpCoord::new(40.0, -74.0, 0.0);
    let at = |e: f64, n: f64| enu_to_geodetic(EnuPoint { e, n, u: 0.0 }, origin);
    let mut a = trp(0, 1, simple(1));
    a.coord = Some(at(0.0, 0.0));
    let mut b = trp(1, 2, simple(2));
    b.coord = Some(at(3_000.0, 0.0));
    let ue = APriori {
        coord: at(1_000.0, 0.0),
        radius_m: 200.0,
    };
    let built = build(&[a.clone(), b.clone()], 0, Some(ue)).unwrap();
    let per = &built.data.nr_dl_prs_assistance_data_list_r16.0[0]
        .nr_dl_prs_assistance_data_per_freq_r16
        .0;
    let unit = 4.0 / (15_000.0 * 2_048.0);
    // d_B − d_A = 2000 − 1000 m.
    let want = (1_000.0 / SPEED_OF_LIGHT_M_S / unit).round() as i16;
    assert_eq!(per[1].nr_dl_prs_expected_rstd_r16.0, want);
    let window = ((400.0 / SPEED_OF_LIGHT_M_S / unit).ceil() as u8) + 1;
    assert_eq!(per[1].nr_dl_prs_expected_rstd_uncertainty_r16.0, window);
    assert_eq!(per[0].nr_dl_prs_expected_rstd_r16.0, 0, "the reference");
    assert_eq!(per[0].nr_dl_prs_expected_rstd_uncertainty_r16.0, 0);

    // 200 km away: beyond ±500 µs (150 km), so B is left out.
    b.coord = Some(at(201_000.0, 0.0));
    let built = build(&[a, b], 0, Some(ue)).unwrap();
    assert_eq!(built.dl_prs_ids, vec![0]);
}

/// The SFN offset's sub-millisecond remainder is part of the expected RSTD.
#[test]
fn the_sub_millisecond_sfn_offset_is_in_the_expected_rstd() {
    let mut a = trp(0, 1, simple(1));
    let mut b = trp(1, 2, simple(2));
    a.sfn_init = Some(t1900(0.0));
    b.sfn_init = Some(t1900(0.010_2)); // 1 frame, 0 subframes, 200 µs
    let built = build(&[a, b], 0, None).unwrap();
    let t = &built.data.nr_dl_prs_assistance_data_list_r16.0[0]
        .nr_dl_prs_assistance_data_per_freq_r16
        .0[1];
    assert_eq!(t.nr_dl_prs_sfn0_offset_r16.sfn_offset_r16.0, 1);
    assert_eq!(t.nr_dl_prs_sfn0_offset_r16.integer_subframe_offset_r16.0, 0);
    let unit: f64 = 4.0 / (15_000.0 * 2_048.0);
    assert_eq!(
        t.nr_dl_prs_expected_rstd_r16.0,
        (200e-6_f64 / unit).round() as i16
    );
}

/// An NRPPa CGI-NR's BCD PLMN (filler F for a two-digit MNC) and 36-bit cell.
#[test]
fn an_nrppa_cgi_becomes_an_ncgi() {
    let cgi = |plmn: [u8; 3], cell: u64| CGI_NR {
        plmn_identity: PLMN_Identity(plmn.to_vec()),
        n_rcell_identifier: NRCellIdentifier((0..36).rev().map(|i| (cell >> i) & 1 == 1).collect()),
        ie_extensions: None,
    };
    let n = Ncgi::from_nrppa(&cgi([0x00, 0xf1, 0x10], 0x1_2345_6789)).unwrap();
    assert_eq!(n.mcc, [0, 0, 1]);
    assert_eq!(n.mnc, vec![0, 1]);
    assert_eq!(n.cell, 0x1_2345_6789);
    assert!(n.matches("001", "01", "123456789"));
    assert!(!n.matches("001", "001", "123456789"));
    let three = Ncgi::from_nrppa(&cgi([0x13, 0x00, 0x62], 5)).unwrap();
    assert_eq!((three.mcc, three.mnc.clone()), ([3, 1, 0], vec![2, 6, 0]));
    let lpp = three.to_lpp();
    assert_eq!(lpp.nr_cellidentity_r15.0.len(), 36);
}
