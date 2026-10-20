//! Cross-codec checks: every LPP-Message lmfd builds with the hand-written
//! `nextgcore-asn1c::lpp` codec must decode under this generated codec and
//! re-encode to the same octets, and hand-derived X.691 UPER octets pin both.

use super::*;
use bitvec::prelude::*;
use nextgcore_asn1c::lpp::capabilities::{
    CommonIEsProvideCapabilities, CommonIEsRequestCapabilities, EcidProvideCapabilities,
    EcidRequestCapabilities, ProvideCapabilities, ProvideCapabilitiesR9, RequestCapabilities,
    RequestCapabilitiesR9,
};
use nextgcore_asn1c::lpp::ecid::{
    EcidProvideLocationInformation, EcidRequestLocationInformation,
    EcidSignalMeasurementInformation, MeasuredResultsElement, ProvideLocationInformation,
    ProvideLocationInformationR9, RequestLocationInformation, RequestLocationInformationR9,
};
use nextgcore_asn1c::lpp::message::{LppMessage, LppMessageBody, MessageBodyC1};
use nextgcore_asn1c::lpp::nr_dl_tdoa::{
    DlPrsIdInfo, NrDlTdoaMeasElement, NrDlTdoaMeasList, NrDlTdoaProvideLocationInformation,
    NrDlTdoaRequestLocationInformation, NrDlTdoaSignalMeasurementInformation, NrRstd, NrSlot,
    NrTimeStamp, NrTimingQuality,
};
use nextgcore_asn1c::lpp::nr_multi_rtt::{
    NrMultiRttMeasElement, NrMultiRttMeasList, NrMultiRttProvideLocationInformation,
    NrMultiRttSignalMeasurementInformation, NrUeRxTxTimeDiff,
};
use nextgcore_asn1c::lpp::types::{Initiator, LppTransactionId, TransactionNumber};

fn bits(values: &[bool]) -> BitVec<u8, Msb0> {
    values.iter().copied().collect()
}

fn tid(initiator: Initiator, n: u8) -> Option<LppTransactionId> {
    Some(LppTransactionId {
        initiator,
        transaction_number: TransactionNumber(n),
    })
}

fn envelope(t: Option<LppTransactionId>, end: bool, body: MessageBodyC1) -> LppMessage {
    LppMessage {
        transaction_id: t,
        end_transaction: end,
        sequence_number: None,
        acknowledgement: None,
        message_body: Some(LppMessageBody::C1(body)),
    }
}

/// Encode with the hand-written codec, then decode and re-encode with the
/// generated one; the octets must not move.
fn assert_agrees(label: &str, msg: &LppMessage) -> Vec<u8> {
    let hand = msg
        .encode()
        .unwrap_or_else(|e| panic!("{label}: hand encode: {e:?}"))
        .to_vec();
    let generated = decode(&hand).unwrap_or_else(|e| panic!("{label}: generated decode: {e:?}"));
    let again = encode(&generated).unwrap_or_else(|e| panic!("{label}: generated encode: {e:?}"));
    assert_eq!(again, hand, "{label}: generated re-encode differs");
    hand
}

fn element(pci: u16, arfcn: u32) -> MeasuredResultsElement {
    MeasuredResultsElement {
        phys_cell_id: pci,
        arfcn_eutra: arfcn,
        system_frame_number: None,
        rsrp_result: Some(50),
        rsrq_result: Some(20),
        ue_rx_tx_time_diff: None,
    }
}

/// RequestCapabilities { commonIEs, ecid } from the target device, transaction 1.
/// UPER, hand-derived: LPP-Message preamble 1001 | transactionID ext 0,
/// targetDevice 01, 00000001 | endTransaction 0 | body c1 0, index 0 0000 |
/// criticalExtensions c1 0, r9 00 | r9-IEs ext 0, opts 10010 |
/// CommonIEsRequestCapabilities ext 0 | ECID-RequestCapabilities ext 0.
const REQUEST_CAPABILITIES: [u8; 4] = [0x92, 0x02, 0x00, 0x48];

/// ProvideCapabilities { commonIEs, ecid '11000'B }, end of transaction:
/// as above with endTransaction 1 and body index 1 (0001), then
/// ECID-ProvideCapabilities ext 0, SIZE(1..8) length-1 = 4 (100), bits 11000.
const PROVIDE_CAPABILITIES: [u8; 5] = [0x92, 0x03, 0x08, 0x48, 0x98];

/// RequestLocationInformation { ecid '11000'B } from the location server,
/// transaction 0, end of transaction -- the vector nextgcore-asn1c derived.
const REQUEST_LOCATION_INFORMATION: [u8; 5] = [0x90, 0x01, 0x20, 0x09, 0x30];

/// ProvideLocationInformation { ecid { signalMeasurementInformation {
/// measuredResultsList [ { physCellId 42, arfcnEUTRA 1850, rsrp 50, rsrq 20 } ] } } }
/// from the target device, transaction 7, end of transaction: preamble 1001 |
/// tid 0 01 00000111 | end 1 | c1 0, index 5 0101 | crit 0 00 | r9-IEs ext 0,
/// opts 00010 | ECID-Provide ext 0, opts 10 | SignalMeas ext 0, opt 0 |
/// list SIZE(1..32) 00000 | element ext 0, opts 00110, physCellId 9 bits,
/// arfcnEUTRA 16 bits, rsrp 7 bits, rsrq 6 bits | pad.
const PROVIDE_LOCATION_INFORMATION: [u8; 11] = [
    0x92, 0x0f, 0x28, 0x09, 0x00, 0x18, 0x54, 0x0e, 0x74, 0xc9, 0x40,
];

#[test]
fn request_capabilities_matches_x691_in_both_codecs() {
    let msg = envelope(
        tid(Initiator::TargetDevice, 1),
        false,
        MessageBodyC1::RequestCapabilities(RequestCapabilities {
            ies: RequestCapabilitiesR9 {
                common: Some(CommonIEsRequestCapabilities),
                ecid: Some(EcidRequestCapabilities),
            },
        }),
    );
    assert_eq!(
        assert_agrees("RequestCapabilities", &msg),
        REQUEST_CAPABILITIES
    );
}

#[test]
fn provide_capabilities_matches_x691_in_both_codecs() {
    let msg = envelope(
        tid(Initiator::TargetDevice, 1),
        true,
        MessageBodyC1::ProvideCapabilities(ProvideCapabilities {
            ies: ProvideCapabilitiesR9 {
                common: Some(CommonIEsProvideCapabilities),
                ecid: Some(EcidProvideCapabilities {
                    ecid_meas_supported: bits(&[true, true, false, false, false]),
                }),
            },
        }),
    );
    assert_eq!(
        assert_agrees("ProvideCapabilities", &msg),
        PROVIDE_CAPABILITIES
    );
}

#[test]
fn request_location_information_matches_x691_in_both_codecs() {
    let msg = envelope(
        tid(Initiator::LocationServer, 0),
        true,
        MessageBodyC1::RequestLocationInformation(RequestLocationInformation {
            ies: RequestLocationInformationR9 {
                ecid: Some(EcidRequestLocationInformation {
                    requested_measurements: bits(&[true, true, false, false, false]),
                }),
                nr_multi_rtt: None,
                nr_dl_tdoa: None,
            },
        }),
    );
    assert_eq!(
        assert_agrees("RequestLocationInformation", &msg),
        REQUEST_LOCATION_INFORMATION
    );
}

#[test]
fn provide_location_information_matches_x691_in_both_codecs() {
    let msg = envelope(
        tid(Initiator::TargetDevice, 7),
        true,
        MessageBodyC1::ProvideLocationInformation(ProvideLocationInformation {
            ies: ProvideLocationInformationR9 {
                nr_multi_rtt: None,
                ecid: Some(EcidProvideLocationInformation {
                    signal_measurement_information: Some(EcidSignalMeasurementInformation {
                        primary_cell_measured_results: None,
                        measured_results_list: vec![element(42, 1850)],
                    }),
                    ecid_error: None,
                }),
                nr_dl_tdoa: None,
                sidelink_ranging: None,
            },
        }),
    );
    assert_eq!(
        assert_agrees("ProvideLocationInformation", &msg),
        PROVIDE_LOCATION_INFORMATION
    );
}

#[test]
fn request_location_information_variants_agree() {
    for n in [0u8, 1, 127, 255] {
        for meas in [&[true][..], &[true, false, true], &[true; 8]] {
            let ecid = envelope(
                tid(Initiator::LocationServer, n),
                n % 2 == 0,
                MessageBodyC1::RequestLocationInformation(RequestLocationInformation {
                    ies: RequestLocationInformationR9 {
                        ecid: Some(EcidRequestLocationInformation {
                            requested_measurements: bits(meas),
                        }),
                        nr_multi_rtt: None,
                        nr_dl_tdoa: None,
                    },
                }),
            );
            assert_agrees(&format!("ecid n {n} meas {meas:?}"), &ecid);
        }
    }
}

/// nextgsim #253: the forked asn1-compiler generates no SEQUENCE extension
/// additions, and every NR method in LPP (nr-DL-TDOA, nr-Multi-RTT, ...) lives
/// in an addition group of the r9 IEs. Such a message decodes WITHOUT error and
/// loses its NR content, so lmfd's NR positioning cannot move to this codec
/// until the fork is fixed. This pins the limitation; once #253 lands it fails,
/// and these messages belong in the agreement tests above.
fn assert_addition_is_dropped(label: &str, msg: &LppMessage) {
    let hand = msg.encode().unwrap().to_vec();
    let generated = decode(&hand).unwrap_or_else(|e| panic!("{label}: generated decode: {e:?}"));
    let again = encode(&generated).unwrap();
    assert!(
        again.len() < hand.len(),
        "{label}: the generated codec now keeps extension additions (nextgsim #253 fixed?) -- \
         move this case into the agreement tests"
    );
}

#[test]
fn nr_methods_in_extension_additions_are_dropped_until_nextgsim_253() {
    for n in [0u8, 255] {
        for meas in [&[true][..], &[true, false, true]] {
            let tdoa = envelope(
                tid(Initiator::LocationServer, n),
                false,
                MessageBodyC1::RequestLocationInformation(RequestLocationInformation {
                    ies: RequestLocationInformationR9 {
                        ecid: None,
                        nr_multi_rtt: None,
                        nr_dl_tdoa: Some(NrDlTdoaRequestLocationInformation {
                            rstd_measurement_info_request: n % 2 == 1,
                            requested_measurements: bits(meas),
                            assistance_availability: true,
                            additional_paths: n == 0,
                        }),
                    },
                }),
            );
            assert_addition_is_dropped(&format!("nr-dl-tdoa request n {n} meas {meas:?}"), &tdoa);
        }
    }
    for msg in nr_provide_messages() {
        assert_addition_is_dropped("nr provide", &msg);
    }
}

fn timestamp() -> NrTimeStamp {
    NrTimeStamp {
        dl_prs_id: 5,
        nr_phys_cell_id: Some(123),
        nr_arfcn: None,
        nr_sfn: 700,
        nr_slot: NrSlot::Scs30(11),
    }
}

#[test]
fn provide_location_information_variants_agree() {
    for (pci, arfcn) in [(0u16, 0u32), (503, 65535), (42, 1850)] {
        let msg = envelope(
            tid(Initiator::TargetDevice, 9),
            true,
            MessageBodyC1::ProvideLocationInformation(ProvideLocationInformation {
                ies: ProvideLocationInformationR9 {
                    nr_multi_rtt: None,
                    ecid: Some(EcidProvideLocationInformation {
                        signal_measurement_information: Some(EcidSignalMeasurementInformation {
                            primary_cell_measured_results: Some(element(pci, arfcn)),
                            measured_results_list: vec![element(pci, arfcn); 3],
                        }),
                        ecid_error: None,
                    }),
                    nr_dl_tdoa: None,
                    sidelink_ranging: None,
                },
            }),
        );
        assert_agrees(&format!("ecid {pci}/{arfcn}"), &msg);
    }
}

#[test]
fn minimal_message_agrees() {
    let msg = LppMessage {
        transaction_id: None,
        end_transaction: false,
        sequence_number: None,
        acknowledgement: None,
        message_body: None,
    };
    assert_eq!(assert_agrees("minimal", &msg), [0x00]);
}

fn nr_provide_messages() -> Vec<LppMessage> {
    let mut out = Vec::new();
    for rstd in [NrRstd::K1(0), NrRstd::K1(500_000)] {
        let msg = envelope(
            tid(Initiator::TargetDevice, 9),
            true,
            MessageBodyC1::ProvideLocationInformation(ProvideLocationInformation {
                ies: ProvideLocationInformationR9 {
                    nr_multi_rtt: None,
                    ecid: None,
                    nr_dl_tdoa: Some(NrDlTdoaProvideLocationInformation {
                        signal_measurement_information: Some(
                            NrDlTdoaSignalMeasurementInformation {
                                dl_prs_reference_info: DlPrsIdInfo { dl_prs_id: 5 },
                                meas_list: NrDlTdoaMeasList {
                                    items: vec![NrDlTdoaMeasElement {
                                        dl_prs_id: 5,
                                        nr_phys_cell_id: Some(123),
                                        nr_arfcn: Some(640_000),
                                        nr_time_stamp: timestamp(),
                                        nr_rstd: rstd.clone(),
                                        nr_timing_quality: NrTimingQuality {
                                            timing_quality_value: 12,
                                            timing_quality_resolution: 2,
                                        },
                                        nr_dl_prs_rsrp_result: Some(80),
                                    }],
                                },
                            },
                        ),
                    }),
                    sidelink_ranging: None,
                },
            }),
        );
        out.push(msg);
    }
    let rtt = envelope(
        tid(Initiator::TargetDevice, 13),
        true,
        MessageBodyC1::ProvideLocationInformation(ProvideLocationInformation {
            ies: ProvideLocationInformationR9 {
                ecid: None,
                nr_multi_rtt: Some(NrMultiRttProvideLocationInformation {
                    signal_measurement_information: Some(NrMultiRttSignalMeasurementInformation {
                        meas_list: NrMultiRttMeasList {
                            items: vec![NrMultiRttMeasElement {
                                dl_prs_id: 5,
                                nr_phys_cell_id: Some(123),
                                nr_arfcn: Some(640_000),
                                nr_ue_rx_tx_time_diff: NrUeRxTxTimeDiff::K2(300_000),
                                nr_time_stamp: timestamp(),
                                nr_timing_quality: NrTimingQuality {
                                    timing_quality_value: 12,
                                    timing_quality_resolution: 2,
                                },
                                nr_dl_prs_rsrp_result: Some(80),
                            }],
                        },
                    }),
                }),
                nr_dl_tdoa: None,
                sidelink_ranging: None,
            },
        }),
    );
    out.push(rtt);
    out
}
