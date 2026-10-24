//! Test fixture builders for uplink LPP messages, on the generated codec (#515).
//!
//! These replace the hand-written LPP codec that tests used to build UE input
//! messages with. Each builder was checked byte for byte against the hand-written
//! encoder it replaces before that codec was deleted.

use nextgcore_lpp_gen::generated as lpp;

/// Wrap `ies` in an uplink `LPP-Message` from the target device.
pub(crate) fn provide_location_information(
    transaction_number: u8,
    ies: lpp::ProvideLocationInformation_r9_IEs,
) -> Vec<u8> {
    let msg = lpp::LPP_Message {
        transaction_id: Some(lpp::LPP_TransactionID {
            initiator: lpp::Initiator(lpp::Initiator::TARGET_DEVICE),
            transaction_number: lpp::TransactionNumber(transaction_number),
        }),
        end_transaction: lpp::LPP_MessageEndTransaction(true),
        sequence_number: None,
        acknowledgement: None,
        lpp_message_body: Some(lpp::LPP_MessageBody::C1(
            lpp::LPP_MessageBody_c1::ProvideLocationInformation(lpp::ProvideLocationInformation {
                critical_extensions: lpp::ProvideLocationInformationCriticalExtensions::C1(
                    lpp::ProvideLocationInformationCriticalExtensions_c1::ProvideLocationInformation_r9(ies),
                ),
            }),
        )),
    };
    nextgcore_lpp_gen::encode(&msg).expect("encode LPP fixture")
}

/// An empty `ProvideLocationInformation-r9-IEs`.
pub(crate) fn empty_ies() -> lpp::ProvideLocationInformation_r9_IEs {
    lpp::ProvideLocationInformation_r9_IEs {
        common_i_es_provide_location_information: None,
        a_gnss_provide_location_information: None,
        otdoa_provide_location_information: None,
        ecid_provide_location_information: None,
        epdu_provide_location_information: None,
        extensions: Default::default(),
    }
}

/// One E-CID `MeasuredResultsElement` (TS 37.355 §6.5.3).
pub(crate) fn measured_results_element(
    phys_cell_id: u16,
    arfcn_eutra: u16,
    rsrp: Option<u8>,
    rsrq: Option<u8>,
    ue_rx_tx: Option<u16>,
) -> lpp::MeasuredResultsElement {
    lpp::MeasuredResultsElement {
        phys_cell_id: lpp::MeasuredResultsElementPhysCellId(phys_cell_id),
        cell_global_id: None,
        arfcn_eutra: lpp::ARFCN_ValueEUTRA(arfcn_eutra),
        system_frame_number: None,
        rsrp_result: rsrp.map(lpp::MeasuredResultsElementRsrp_Result),
        rsrq_result: rsrq.map(lpp::MeasuredResultsElementRsrq_Result),
        ue_rx_tx_time_diff: ue_rx_tx.map(lpp::MeasuredResultsElementUe_RxTxTimeDiff),
        extensions: Default::default(),
    }
}

/// An E-CID `ProvideLocationInformation` whose measured-results list is `elements`.
pub(crate) fn ecid_provide(
    transaction_number: u8,
    elements: Vec<lpp::MeasuredResultsElement>,
) -> Vec<u8> {
    let mut ies = empty_ies();
    ies.ecid_provide_location_information = Some(lpp::ECID_ProvideLocationInformation {
        ecid_signal_measurement_information: Some(lpp::ECID_SignalMeasurementInformation {
            primary_cell_measured_results: None,
            measured_results_list: lpp::MeasuredResultsList(elements),
        }),
        ecid_error: None,
    });
    provide_location_information(transaction_number, ies)
}

/// The E-CID report a scripted UE returns: one element, ARFCN 1850, rsrq 20.
pub(crate) fn ecid_lpp(pci: u16, rsrp: u8, ue_rx_tx: u16, transaction_number: u8) -> Vec<u8> {
    ecid_provide(
        transaction_number,
        vec![measured_results_element(
            pci,
            1850,
            Some(rsrp),
            Some(20),
            Some(ue_rx_tx),
        )],
    )
}

/// One nr-Multi-RTT measurement element: DL-PRS ID 5, k0 Rx-Tx difference `k0`,
/// time stamp SFN 700 / scs30 slot 11, timing quality 8 at 1 m, RSRP 90.
pub(crate) fn multi_rtt_element(pci: u16, k0: u32) -> lpp::NR_Multi_RTT_MeasElement_r16 {
    lpp::NR_Multi_RTT_MeasElement_r16 {
        dl_prs_id_r16: lpp::NR_Multi_RTT_MeasElement_r16Dl_PRS_ID_r16(5),
        nr_phys_cell_id_r16: Some(lpp::NR_PhysCellID_r16(pci)),
        nr_cell_global_id_r16: None,
        nr_arfcn_r16: None,
        nr_dl_prs_resource_id_r16: None,
        nr_dl_prs_resource_set_id_r16: None,
        nr_ue_rx_tx_time_diff_r16: lpp::NR_Multi_RTT_MeasElement_r16Nr_UE_RxTxTimeDiff_r16::K0_r16(
            lpp::NR_Multi_RTT_MeasElement_r16Nr_UE_RxTxTimeDiff_r16_k0_r16(k0),
        ),
        nr_additional_path_list_r16: None,
        nr_time_stamp_r16: lpp::NR_TimeStamp_r16 {
            dl_prs_id_r16: lpp::NR_TimeStamp_r16Dl_PRS_ID_r16(5),
            nr_phys_cell_id_r16: None,
            nr_cell_global_id_r16: None,
            nr_arfcn_r16: None,
            nr_sfn_r16: lpp::NR_TimeStamp_r16Nr_SFN_r16(700),
            nr_slot_r16: lpp::NR_TimeStamp_r16Nr_Slot_r16::Scs30_r16(
                lpp::NR_TimeStamp_r16Nr_Slot_r16_scs30_r16(11),
            ),
            extensions: Default::default(),
        },
        nr_timing_quality_r16: lpp::NR_TimingQuality_r16 {
            timing_quality_value_r16: lpp::NR_TimingQuality_r16TimingQualityValue_r16(8),
            timing_quality_resolution_r16: lpp::NR_TimingQuality_r16TimingQualityResolution_r16(
                lpp::NR_TimingQuality_r16TimingQualityResolution_r16::M1,
            ),
        },
        nr_dl_prs_rsrp_result_r16: Some(
            lpp::NR_Multi_RTT_MeasElement_r16Nr_DL_PRS_RSRP_Result_r16(90),
        ),
        nr_multi_rtt_additional_measurements_r16: None,
        extensions: Default::default(),
    }
}

/// An nr-Multi-RTT `ProvideLocationInformation`, one element per `(pci, k0)`.
pub(crate) fn multi_rtt_lpp(cells: &[(u16, u32)], transaction_number: u8) -> Vec<u8> {
    let mut ies = empty_ies();
    ies.extensions.nr_multi_rtt_provide_location_information_r16 =
        Some(lpp::NR_Multi_RTT_ProvideLocationInformation_r16 {
            nr_multi_rtt_signal_measurement_information_r16: Some(
                lpp::NR_Multi_RTT_SignalMeasurementInformation_r16 {
                    nr_multi_rtt_meas_list_r16: lpp::NR_Multi_RTT_MeasList_r16(
                        cells
                            .iter()
                            .map(|(pci, k0)| multi_rtt_element(*pci, *k0))
                            .collect(),
                    ),
                    nr_nta_offset_r16: None,
                    extensions: Default::default(),
                },
            ),
            nr_multi_rtt_error_r16: None,
            extensions: Default::default(),
        });
    provide_location_information(transaction_number, ies)
}

/// An nr-Multi-RTT `ProvideLocationInformation`, one element per `(DL-PRS ID,
/// pci, k0)` (#903 review: distinct DL-PRS IDs, as a real UE reports them).
pub(crate) fn multi_rtt_lpp_with_prs(cells: &[(u8, u16, u32)], transaction_number: u8) -> Vec<u8> {
    let mut ies = empty_ies();
    ies.extensions.nr_multi_rtt_provide_location_information_r16 =
        Some(lpp::NR_Multi_RTT_ProvideLocationInformation_r16 {
            nr_multi_rtt_signal_measurement_information_r16: Some(
                lpp::NR_Multi_RTT_SignalMeasurementInformation_r16 {
                    nr_multi_rtt_meas_list_r16: lpp::NR_Multi_RTT_MeasList_r16(
                        cells
                            .iter()
                            .map(|(prs, pci, k0)| {
                                let mut e = multi_rtt_element(*pci, *k0);
                                e.dl_prs_id_r16 =
                                    lpp::NR_Multi_RTT_MeasElement_r16Dl_PRS_ID_r16(*prs);
                                e
                            })
                            .collect(),
                    ),
                    nr_nta_offset_r16: None,
                    extensions: Default::default(),
                },
            ),
            nr_multi_rtt_error_r16: None,
            extensions: Default::default(),
        });
    provide_location_information(transaction_number, ies)
}

/// One NR-DL-TDOA measurement element: DL-PRS ID `prs_id`, PCI `pci` when given,
/// RSTD k0 code `k0`, the same time stamp and quality as [`multi_rtt_element`].
pub(crate) fn dl_tdoa_element(
    prs_id: u8,
    pci: Option<u16>,
    k0: u32,
) -> lpp::NR_DL_TDOA_MeasElement_r16 {
    let template = multi_rtt_element(0, 0);
    lpp::NR_DL_TDOA_MeasElement_r16 {
        dl_prs_id_r16: lpp::NR_DL_TDOA_MeasElement_r16Dl_PRS_ID_r16(prs_id),
        nr_phys_cell_id_r16: pci.map(lpp::NR_PhysCellID_r16),
        nr_cell_global_id_r16: None,
        nr_arfcn_r16: None,
        nr_dl_prs_resource_id_r16: None,
        nr_dl_prs_resource_set_id_r16: None,
        nr_time_stamp_r16: template.nr_time_stamp_r16,
        nr_rstd_r16: lpp::NR_DL_TDOA_MeasElement_r16Nr_RSTD_r16::K0_r16(
            lpp::NR_DL_TDOA_MeasElement_r16Nr_RSTD_r16_k0_r16(k0),
        ),
        nr_additional_path_list_r16: None,
        nr_timing_quality_r16: template.nr_timing_quality_r16,
        nr_dl_prs_rsrp_result_r16: Some(lpp::NR_DL_TDOA_MeasElement_r16Nr_DL_PRS_RSRP_Result_r16(
            90,
        )),
        nr_dl_tdoa_additional_measurements_r16: None,
        extensions: Default::default(),
    }
}

/// An NR-DL-TDOA `ProvideLocationInformation`: the reference DL-PRS ID, then one
/// element per `(prs_id, pci, k0)`.
pub(crate) fn dl_tdoa_lpp(
    reference_prs_id: u8,
    neighbours: &[(u8, Option<u16>, u32)],
    transaction_number: u8,
) -> Vec<u8> {
    let mut ies = empty_ies();
    ies.extensions.nr_dl_tdoa_provide_location_information_r16 =
        Some(lpp::NR_DL_TDOA_ProvideLocationInformation_r16 {
            nr_dl_tdoa_signal_measurement_information_r16: Some(
                lpp::NR_DL_TDOA_SignalMeasurementInformation_r16 {
                    dl_prs_reference_info_r16: lpp::DL_PRS_ID_Info_r16 {
                        dl_prs_id_r16: lpp::DL_PRS_ID_Info_r16Dl_PRS_ID_r16(reference_prs_id),
                        nr_dl_prs_resource_id_list_r16: None,
                        nr_dl_prs_resource_set_id_r16: None,
                    },
                    nr_dl_tdoa_meas_list_r16: lpp::NR_DL_TDOA_MeasList_r16(
                        neighbours
                            .iter()
                            .map(|(prs, pci, k0)| dl_tdoa_element(*prs, *pci, *k0))
                            .collect(),
                    ),
                    extensions: Default::default(),
                },
            ),
            nr_dl_tdoa_location_information_r16: None,
            nr_dl_tdoa_error_r16: None,
            extensions: Default::default(),
        });
    provide_location_information(transaction_number, ies)
}

/// #903 review: the answer to a Multi-RTT + DL-TDOA request, carrying both
/// measurement sets in one `ProvideLocationInformation`.
pub(crate) fn multi_rtt_and_dl_tdoa_lpp(
    cells: &[(u8, u16, u32)],
    reference_prs_id: u8,
    neighbours: &[(u8, Option<u16>, u32)],
    transaction_number: u8,
) -> Vec<u8> {
    let mut ies = empty_ies();
    ies.extensions.nr_multi_rtt_provide_location_information_r16 =
        Some(lpp::NR_Multi_RTT_ProvideLocationInformation_r16 {
            nr_multi_rtt_signal_measurement_information_r16: Some(
                lpp::NR_Multi_RTT_SignalMeasurementInformation_r16 {
                    nr_multi_rtt_meas_list_r16: lpp::NR_Multi_RTT_MeasList_r16(
                        cells
                            .iter()
                            .map(|(prs, pci, k0)| {
                                let mut e = multi_rtt_element(*pci, *k0);
                                e.dl_prs_id_r16 =
                                    lpp::NR_Multi_RTT_MeasElement_r16Dl_PRS_ID_r16(*prs);
                                e
                            })
                            .collect(),
                    ),
                    nr_nta_offset_r16: None,
                    extensions: Default::default(),
                },
            ),
            nr_multi_rtt_error_r16: None,
            extensions: Default::default(),
        });
    ies.extensions.nr_dl_tdoa_provide_location_information_r16 =
        Some(lpp::NR_DL_TDOA_ProvideLocationInformation_r16 {
            nr_dl_tdoa_signal_measurement_information_r16: Some(
                lpp::NR_DL_TDOA_SignalMeasurementInformation_r16 {
                    dl_prs_reference_info_r16: lpp::DL_PRS_ID_Info_r16 {
                        dl_prs_id_r16: lpp::DL_PRS_ID_Info_r16Dl_PRS_ID_r16(reference_prs_id),
                        nr_dl_prs_resource_id_list_r16: None,
                        nr_dl_prs_resource_set_id_r16: None,
                    },
                    nr_dl_tdoa_meas_list_r16: lpp::NR_DL_TDOA_MeasList_r16(
                        neighbours
                            .iter()
                            .map(|(prs, pci, k0)| dl_tdoa_element(*prs, *pci, *k0))
                            .collect(),
                    ),
                    extensions: Default::default(),
                },
            ),
            nr_dl_tdoa_location_information_r16: None,
            nr_dl_tdoa_error_r16: None,
            extensions: Default::default(),
        });
    provide_location_information(transaction_number, ies)
}

/// An NR E-CID `ProvideLocationInformation` (TS 37.355 Rel-16): the primary cell
/// `pci` with SS-RSRP `ss_rsrp` and SS-RSRQ `ss_rsrq` (report values), and one
/// neighbour per `(pci, ss_rsrp)` with only an SS-RSRP.
pub(crate) fn nr_ecid_lpp(
    pci: u16,
    ss_rsrp: u8,
    ss_rsrq: u8,
    neighbours: &[(u16, u8)],
    transaction_number: u8,
) -> Vec<u8> {
    let element = |pci: u16, rsrp: u8, rsrq: Option<u8>| lpp::NR_MeasuredResultsElement_r16 {
        nr_phys_cell_id_r16: lpp::NR_PhysCellID_r16(pci),
        nr_arfcn_r16: lpp::NR_MeasuredResultsElement_r16Nr_ARFCN_r16::Ssb_ARFCN_r16(
            lpp::ARFCN_ValueNR_r15(632_628),
        ),
        nr_cell_global_id_r16: None,
        system_frame_number_r16: None,
        results_ssb_cell_r16: Some(lpp::MeasQuantityResults_r16 {
            nr_rsrp_r16: Some(lpp::MeasQuantityResults_r16Nr_RSRP_r16(rsrp)),
            nr_rsrq_r16: rsrq.map(lpp::MeasQuantityResults_r16Nr_RSRQ_r16),
        }),
        results_csi_rs_cell_r16: None,
        results_ssb_indexes_r16: None,
        results_csi_rs_indexes_r16: None,
    };
    let mut ies = empty_ies();
    ies.extensions.nr_ecid_provide_location_information_r16 =
        Some(lpp::NR_ECID_ProvideLocationInformation_r16 {
            nr_ecid_signal_measurement_information_r16: Some(
                lpp::NR_ECID_SignalMeasurementInformation_r16 {
                    nr_primary_cell_measured_results_r16: element(pci, ss_rsrp, Some(ss_rsrq)),
                    nr_measured_results_list_r16: (!neighbours.is_empty()).then(|| {
                        lpp::NR_MeasuredResultsList_r16(
                            neighbours
                                .iter()
                                .map(|(p, r)| element(*p, *r, None))
                                .collect(),
                        )
                    }),
                },
            ),
            nr_ecid_error_r16: None,
        });
    provide_location_information(transaction_number, ies)
}

/// An uplink `ProvideCapabilities` answering transaction `transaction_number`
/// (#906, TS 37.355 §5.1.1 step 2: endTransaction TRUE) that reports E-CID only:
/// E-UTRA `ecid-ProvideCapabilities` and/or Rel-16 `nr-ECID-ProvideCapabilities-r16`.
/// Built from the captured E-UTRA E-CID vector `9203084858` with its transaction
/// number and flavours replaced.
pub(crate) fn ecid_capabilities(transaction_number: u8, eutra: bool, nr: bool) -> Vec<u8> {
    let bytes = crate::lpp_equivalence_tests::unhex("9203084858");
    let mut msg = nextgcore_lpp_gen::decode(&bytes).expect("captured vector decodes");
    if let Some(t) = msg.transaction_id.as_mut() {
        t.transaction_number = lpp::TransactionNumber(transaction_number);
    }
    let Some(lpp::LPP_MessageBody::C1(lpp::LPP_MessageBody_c1::ProvideCapabilities(caps))) =
        msg.lpp_message_body.as_mut()
    else {
        panic!("captured vector is a ProvideCapabilities");
    };
    let lpp::ProvideCapabilitiesCriticalExtensions::C1(
        lpp::ProvideCapabilitiesCriticalExtensions_c1::ProvideCapabilities_r9(ies),
    ) = &mut caps.critical_extensions
    else {
        panic!("r9 IEs");
    };
    if !eutra {
        ies.ecid_provide_capabilities = None;
    }
    if nr {
        ies.extensions.nr_ecid_provide_capabilities_r16 =
            Some(lpp::NR_ECID_ProvideCapabilities_r16 {
                nr_ecid_meas_supported_r16:
                    lpp::NR_ECID_ProvideCapabilities_r16Nr_ECID_MeasSupported_r16(
                        [true, true].into_iter().collect(),
                    ),
                periodical_reporting_r16: None,
                triggered_reporting_r16: None,
                extensions: Default::default(),
            });
    }
    nextgcore_lpp_gen::encode(&msg).expect("encode LPP fixture")
}
