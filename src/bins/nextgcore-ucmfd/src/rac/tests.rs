//! #585: transcoding and paging derivation, driven with real UPER encodings of the
//! TS 38.331 / TS 36.331 types (built with the generated codecs, the way nextgsim's
//! UE builds its UE-NR-Capability).

use super::*;

/// #726: X.691 golden bytes, derived without the generated codecs.
mod golden;

/// A minimal valid `UE-NR-Capability` supporting `bands`.
pub(crate) fn ue_nr_capability(bands: &[u16]) -> Vec<u8> {
    use n::*;
    let cap = UE_NR_Capability {
        access_stratum_release: AccessStratumRelease(AccessStratumRelease::REL15),
        pdcp_parameters: PDCP_Parameters {
            extensions: Default::default(),
            supported_rohc_profiles: PDCP_ParametersSupportedROHC_Profiles {
                profile0x0000: PDCP_ParametersSupportedROHC_ProfilesProfile0x0000(false),
                profile0x0001: PDCP_ParametersSupportedROHC_ProfilesProfile0x0001(false),
                profile0x0002: PDCP_ParametersSupportedROHC_ProfilesProfile0x0002(false),
                profile0x0003: PDCP_ParametersSupportedROHC_ProfilesProfile0x0003(false),
                profile0x0004: PDCP_ParametersSupportedROHC_ProfilesProfile0x0004(false),
                profile0x0006: PDCP_ParametersSupportedROHC_ProfilesProfile0x0006(false),
                profile0x0101: PDCP_ParametersSupportedROHC_ProfilesProfile0x0101(false),
                profile0x0102: PDCP_ParametersSupportedROHC_ProfilesProfile0x0102(false),
                profile0x0103: PDCP_ParametersSupportedROHC_ProfilesProfile0x0103(false),
                profile0x0104: PDCP_ParametersSupportedROHC_ProfilesProfile0x0104(false),
            },
            max_number_rohc_context_sessions: PDCP_ParametersMaxNumberROHC_ContextSessions(
                PDCP_ParametersMaxNumberROHC_ContextSessions::CS2,
            ),
            uplink_only_rohc_profiles: None,
            continue_rohc_context: None,
            out_of_order_delivery: None,
            short_sn: None,
            pdcp_duplication_srb: None,
            pdcp_duplication_mcg_or_scg_drb: None,
        },
        rlc_parameters: None,
        mac_parameters: None,
        phy_parameters: Phy_Parameters {
            phy_parameters_common: None,
            phy_parameters_xdd_diff: None,
            phy_parameters_frx_diff: None,
            phy_parameters_fr1: None,
            phy_parameters_fr2: None,
        },
        rf_parameters: RF_Parameters {
            extensions: Default::default(),
            supported_band_list_nr: RF_ParametersSupportedBandListNR(
                bands
                    .iter()
                    .map(|b| BandNR {
                        extensions: Default::default(),
                        band_nr: FreqBandIndicatorNR(*b),
                        modified_mpr_behaviour: None,
                        mimo_parameters_per_band: None,
                        extended_cp: None,
                        multiple_tci: None,
                        bwp_without_restriction: None,
                        bwp_same_numerology: None,
                        bwp_diff_numerology: None,
                        cross_carrier_scheduling_same_scs: None,
                        pdsch_256qam_fr2: None,
                        pusch_256qam: None,
                        ue_power_class: None,
                        rate_matching_lte_crs: None,
                        channel_b_ws_dl: None,
                        channel_b_ws_ul: None,
                    })
                    .collect(),
            ),
            supported_band_combination_list: None,
            applied_freq_band_list_filter: None,
        },
        meas_and_mob_parameters: None,
        fdd_add_ue_nr_capabilities: None,
        tdd_add_ue_nr_capabilities: None,
        fr1_add_ue_nr_capabilities: None,
        fr2_add_ue_nr_capabilities: None,
        feature_sets: None,
        feature_set_combinations: None,
        late_non_critical_extension: None,
        non_critical_extension: None,
    };
    nr::encode(&cap).unwrap()
}

/// A minimal valid `UE-EUTRA-Capability` supporting `bands`.
pub(crate) fn ue_eutra_capability(bands: &[u8]) -> Vec<u8> {
    use l::*;
    let cap = UE_EUTRA_Capability {
        access_stratum_release: AccessStratumRelease(AccessStratumRelease::REL15),
        ue_category: UE_EUTRA_CapabilityUe_Category(4),
        pdcp_parameters: PDCP_Parameters {
            supported_rohc_profiles: ROHC_ProfileSupportList_r15 {
                profile0x0001_r15: ROHC_ProfileSupportList_r15Profile0x0001_r15(false),
                profile0x0002_r15: ROHC_ProfileSupportList_r15Profile0x0002_r15(false),
                profile0x0003_r15: ROHC_ProfileSupportList_r15Profile0x0003_r15(false),
                profile0x0004_r15: ROHC_ProfileSupportList_r15Profile0x0004_r15(false),
                profile0x0006_r15: ROHC_ProfileSupportList_r15Profile0x0006_r15(false),
                profile0x0101_r15: ROHC_ProfileSupportList_r15Profile0x0101_r15(false),
                profile0x0102_r15: ROHC_ProfileSupportList_r15Profile0x0102_r15(false),
                profile0x0103_r15: ROHC_ProfileSupportList_r15Profile0x0103_r15(false),
                profile0x0104_r15: ROHC_ProfileSupportList_r15Profile0x0104_r15(false),
            },
            max_number_rohc_context_sessions: None,
        },
        phy_layer_parameters: PhyLayerParameters {
            ue_tx_antenna_selection_supported: PhyLayerParametersUe_TxAntennaSelectionSupported(
                false,
            ),
            ue_specific_ref_sigs_supported: PhyLayerParametersUe_SpecificRefSigsSupported(false),
        },
        rf_parameters: RF_Parameters {
            supported_band_list_eutra: SupportedBandListEUTRA(
                bands
                    .iter()
                    .map(|b| SupportedBandEUTRA {
                        band_eutra: FreqBandIndicator(*b),
                        half_duplex: SupportedBandEUTRAHalfDuplex(false),
                    })
                    .collect(),
            ),
        },
        meas_parameters: MeasParameters {
            band_list_eutra: BandListEUTRA(
                bands
                    .iter()
                    .map(|_| BandInfoEUTRA {
                        inter_freq_band_list: InterFreqBandList(
                            bands
                                .iter()
                                .map(|_| InterFreqBandInfo {
                                    inter_freq_need_for_gaps: InterFreqBandInfoInterFreqNeedForGaps(
                                        true,
                                    ),
                                })
                                .collect(),
                        ),
                        inter_rat_band_list: None,
                    })
                    .collect(),
            ),
        },
        feature_group_indicators: None,
        inter_rat_parameters: UE_EUTRA_CapabilityInterRAT_Parameters {
            utra_fdd: None,
            utra_tdd128: None,
            utra_tdd384: None,
            utra_tdd768: None,
            geran: None,
            cdma2000_hrpd: None,
            cdma2000_1x_rtt: None,
        },
        non_critical_extension: None,
    };
    lte::encode(&cap).unwrap()
}

/// A 5GS-format capability: NR (bands 78, 1), E-UTRA (bands 3, 7) and a UTRA-FDD
/// container that must never reach the dictionary's other format.
pub(crate) fn cap_5gs() -> Vec<u8> {
    let list = n::UE_CapabilityRAT_ContainerList(vec![
        n::UE_CapabilityRAT_Container {
            rat_type: n::RAT_Type(n::RAT_Type::NR),
            ue_capability_rat_container: n::UE_CapabilityRAT_ContainerUe_CapabilityRAT_Container(
                ue_nr_capability(&[78, 1]),
            ),
        },
        n::UE_CapabilityRAT_Container {
            rat_type: n::RAT_Type(n::RAT_Type::EUTRA),
            ue_capability_rat_container: n::UE_CapabilityRAT_ContainerUe_CapabilityRAT_Container(
                ue_eutra_capability(&[3, 7]),
            ),
        },
        n::UE_CapabilityRAT_Container {
            rat_type: n::RAT_Type(n::RAT_Type::UTRA_FDD_V1610),
            ue_capability_rat_container: n::UE_CapabilityRAT_ContainerUe_CapabilityRAT_Container(
                vec![0xde, 0xad],
            ),
        },
    ]);
    let info = n::UERadioAccessCapabilityInformation {
        critical_extensions: n::UERadioAccessCapabilityInformationCriticalExtensions::C1(
            n::UERadioAccessCapabilityInformationCriticalExtensions_c1::UeRadioAccessCapabilityInformation(
                n::UERadioAccessCapabilityInformation_IEs {
                    ue_radio_access_capability_info:
                        n::UERadioAccessCapabilityInformation_IEsUe_RadioAccessCapabilityInfo(
                            nr::encode(&list).unwrap(),
                        ),
                    non_critical_extension: None,
                },
            ),
        ),
    };
    nr::encode(&info).unwrap()
}

/// An EPS-format capability: E-UTRA (bands 20, 64, 3) and GERAN-PS. With
/// `category_0`, the UE reported a `ue-RadioPagingInfo-r12` with ue-Category-v1250.
pub(crate) fn cap_eps(category_0: bool) -> Vec<u8> {
    let paging = l::UE_RadioPagingInfo_r12 {
        ue_category_v1250: Some(l::UE_RadioPagingInfo_r12Ue_Category_v1250(0)),
        extensions: Default::default(),
    };
    let msg = l::UECapabilityInformation {
        rrc_transaction_identifier: l::RRC_TransactionIdentifier(2),
        critical_extensions: l::UECapabilityInformationCriticalExtensions::C1(
            l::UECapabilityInformationCriticalExtensions_c1::UeCapabilityInformation_r8(
                l::UECapabilityInformation_r8_IEs {
                    ue_capability_rat_container_list: l::UE_CapabilityRAT_ContainerList(vec![
                        l::UE_CapabilityRAT_Container {
                            rat_type: l::RAT_Type(l::RAT_Type::EUTRA),
                            ue_capability_rat_container:
                                l::UE_CapabilityRAT_ContainerUeCapabilityRAT_Container(
                                    ue_eutra_capability(&[20, 64, 3]),
                                ),
                        },
                        l::UE_CapabilityRAT_Container {
                            rat_type: l::RAT_Type(l::RAT_Type::GERAN_PS),
                            ue_capability_rat_container:
                                l::UE_CapabilityRAT_ContainerUeCapabilityRAT_Container(vec![1]),
                        },
                    ]),
                    non_critical_extension: category_0.then_some(
                        l::UECapabilityInformation_v8a0_IEs {
                            late_non_critical_extension: None,
                            non_critical_extension: Some(l::UECapabilityInformation_v1250_IEs {
                                ue_radio_paging_info_r12: Some(paging),
                                non_critical_extension: None,
                            }),
                        },
                    ),
                },
            ),
        ),
    };
    let info = l::UERadioAccessCapabilityInformation {
        critical_extensions: l::UERadioAccessCapabilityInformationCriticalExtensions::C1(
            l::UERadioAccessCapabilityInformationCriticalExtensions_c1::UeRadioAccessCapabilityInformation_r8(
                l::UERadioAccessCapabilityInformation_r8_IEs {
                    ue_radio_access_capability_info:
                        l::UERadioAccessCapabilityInformation_r8_IEsUe_RadioAccessCapabilityInfo(
                            lte::encode(&msg).unwrap(),
                        ),
                    non_critical_extension: None,
                },
            ),
        ),
    };
    lte::encode(&info).unwrap()
}

#[test]
fn a_5gs_capability_transcodes_to_eps_and_back_with_every_container_intact() {
    let eps = transcode_5gs_to_eps(&cap_5gs()).unwrap();
    let parsed = parse_eps(&eps).unwrap();
    // The two RATs both formats carry, mapped into the TS 36.331 enumeration and
    // with their bytes unchanged. UTRA-FDD is dropped (TS 23.502 §5.2.18.2.1).
    assert_eq!(
        parsed.containers,
        [
            (Rat::Nr, ue_nr_capability(&[78, 1])),
            (Rat::Eutra, ue_eutra_capability(&[3, 7])),
        ]
    );
    // On the wire, rat-Type is the TS 36.331 value: nr is 5 there and 0 in TS 38.331.
    let info: l::UERadioAccessCapabilityInformation = lte::decode(&eps).unwrap();
    let l::UERadioAccessCapabilityInformationCriticalExtensions::C1(
        l::UERadioAccessCapabilityInformationCriticalExtensions_c1::UeRadioAccessCapabilityInformation_r8(ies),
    ) = info.critical_extensions
    else {
        panic!("not r8")
    };
    let msg: l::UECapabilityInformation =
        lte::decode(&ies.ue_radio_access_capability_info.0).unwrap();
    let l::UECapabilityInformationCriticalExtensions::C1(
        l::UECapabilityInformationCriticalExtensions_c1::UeCapabilityInformation_r8(r8),
    ) = msg.critical_extensions
    else {
        panic!("not r8")
    };
    assert_eq!(
        r8.ue_capability_rat_container_list.0[0].rat_type.0,
        l::RAT_Type::NR
    );
    assert_eq!(l::RAT_Type::NR, 5);

    // And back: the same containers in the TS 38.331 form.
    let back = transcode_eps_to_5gs(&eps).unwrap();
    assert_eq!(parse_5gs(&back).unwrap().containers, parsed.containers);
}

#[test]
fn an_eps_capability_transcodes_to_5gs_without_geran() {
    let fivegs = transcode_eps_to_5gs(&cap_eps(false)).unwrap();
    assert_eq!(
        parse_5gs(&fivegs).unwrap().containers,
        [(Rat::Eutra, ue_eutra_capability(&[20, 64, 3]))]
    );
}

#[test]
fn bytes_that_are_not_a_capability_are_refused_not_guessed() {
    assert!(matches!(
        transcode_5gs_to_eps(&[1, 2, 3]),
        Err(RacError::Undecodable(_))
    ));
    assert!(matches!(
        transcode_eps_to_5gs(&[0xff]),
        Err(RacError::Undecodable(_))
    ));
    assert!(derive_paging_5gs(&[]).is_err());
}

#[test]
fn the_5gs_paging_capability_is_derived_for_nr_and_eutra() {
    let paging = derive_paging_5gs(&cap_5gs()).unwrap();
    // What the AMF puts in NGAP Paging (TS 38.413 §9.3.1.68), as the AMF decodes it.
    let p: g::UERadioCapabilityForPaging =
        ngap::decode_contained::<g::UERadioCapabilityForPaging>(&paging).unwrap();

    let of_nr: n::UERadioPagingInformation =
        nr::decode(&p.ue_radio_capability_for_paging_of_nr.unwrap().0).unwrap();
    let n::UERadioPagingInformationCriticalExtensions::C1(
        n::UERadioPagingInformationCriticalExtensions_c1::UeRadioPagingInformation(ies),
    ) = of_nr.critical_extensions
    else {
        panic!("not c1")
    };
    let bands: Vec<u16> = ies
        .supported_band_list_nr_for_paging
        .unwrap()
        .0
        .iter()
        .map(|b| b.0)
        .collect();
    assert_eq!(bands, [78, 1], "the bands of supportedBandListNR");

    let of_eutra = p.ue_radio_capability_for_paging_of_eutra.unwrap().0;
    assert_eq!(eutra_bands(&of_eutra), [3, 7]);
}

fn eutra_paging(bytes: &[u8]) -> (l::UE_RadioPagingInfo_r12, Vec<u16>) {
    let info: l::UERadioPagingInformation = lte::decode(bytes).unwrap();
    let l::UERadioPagingInformationCriticalExtensions::C1(
        l::UERadioPagingInformationCriticalExtensions_c1::UeRadioPagingInformation_r12(ies),
    ) = info.critical_extensions
    else {
        panic!("not r12")
    };
    let pi: l::UE_RadioPagingInfo_r12 = lte::decode(&ies.ue_radio_paging_info_r12.0).unwrap();
    let bands = ies
        .non_critical_extension
        .and_then(|v| v.supported_band_list_eutra_for_paging_r13)
        .map(|l| l.0.iter().map(|b| b.0).collect())
        .unwrap_or_default();
    (pi, bands)
}

fn eutra_bands(bytes: &[u8]) -> Vec<u16> {
    eutra_paging(bytes).1
}

#[test]
fn the_eps_paging_capability_is_derived_and_keeps_what_the_ue_reported() {
    // maxFBI (64) defers to the v9e0 extension and is not a band: left out.
    let (info, bands) = eutra_paging(&derive_paging_eps(&cap_eps(false)).unwrap());
    assert_eq!(bands, [20, 3]);
    assert_eq!(info.ue_category_v1250, None);

    // A UE-reported ue-RadioPagingInfo-r12 (category 0) is carried over.
    let (info, _) = eutra_paging(&derive_paging_eps(&cap_eps(true)).unwrap());
    assert_eq!(
        info.ue_category_v1250,
        Some(l::UE_RadioPagingInfo_r12Ue_Category_v1250(0))
    );
}

#[test]
fn no_eutra_container_means_no_eps_paging_capability() {
    // An EPS capability that is only GERAN after filtering has nothing to page with.
    let only_nr = transcode_5gs_to_eps(&{
        let list = n::UE_CapabilityRAT_ContainerList(vec![n::UE_CapabilityRAT_Container {
            rat_type: n::RAT_Type(n::RAT_Type::NR),
            ue_capability_rat_container: n::UE_CapabilityRAT_ContainerUe_CapabilityRAT_Container(
                ue_nr_capability(&[78]),
            ),
        }]);
        build_5gs_list(list)
    })
    .unwrap();
    assert_eq!(derive_paging_eps(&only_nr), Err(RacError::NoPagingSource));
}

fn build_5gs_list(list: n::UE_CapabilityRAT_ContainerList) -> Vec<u8> {
    let containers: Vec<(Rat, Vec<u8>)> = list
        .0
        .into_iter()
        .filter_map(|c| Rat::from_nr(c.rat_type.0).map(|r| (r, c.ue_capability_rat_container.0)))
        .collect();
    build_5gs(&containers).unwrap()
}

/// `tests/live_nrf.rs` sends this capability to the real binary. The file is
/// generated from [`cap_5gs`] and must stay equal to it
/// (`UCMF_WRITE_TEST_VECTORS=1` rewrites it).
#[test]
fn the_live_test_vector_is_the_unit_test_capability() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/cap_5gs.bin");
    if std::env::var_os("UCMF_WRITE_TEST_VECTORS").is_some() {
        std::fs::write(path, cap_5gs()).unwrap();
    }
    assert_eq!(std::fs::read(path).unwrap(), cap_5gs());
}
