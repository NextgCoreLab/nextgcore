//! Codec checks for the generated SLPP codec (#557).
//!
//! Every golden here is derived by hand from TS 38.355 V19.2.0 §6 and X.691
//! (unaligned PER), bit by bit, in the doc comment above it. Each golden is
//! checked both ways. It is decoded and the decoded value is compared field by
//! field with the value the derivation names. The value is also built from
//! scratch and encoded, and the result must match the golden byte for byte. A
//! self round trip alone would accept a layout that the encoder and decoder
//! both get wrong.
//!
//! Notation: `|` separates fields. `len` is an unconstrained-length
//! determinant, which is one octet `0nnnnnnn` below 128 (X.691 §11.9.3.6).
//! `ext` is a SEQUENCE or CHOICE extension bit (§19.1, §23.5). `opts` is the
//! SEQUENCE preamble of presence bits (§19.2).

use super::generated::*;
use super::{decode, decode_ie, encode, encode_ie};

/// The sending UE's application layer ID (TS 23.287), as an OCTET STRING.
const UE_APP_ID: [u8; 3] = [0xA5, 0xA5, 0xA5];
/// The peer UE whose SL-PRS was measured.
const PEER_APP_ID: [u8; 3] = [0x5A, 0x5A, 0x5A];

/// RequestCapabilities for SL-RTT from the LMF, transaction 1.
///
/// SLPP-Message is not extensible, so it opens with 7 presence bits:
/// applicationLayerID 0, transactionID 1, sequenceNumber 0, sessionID 0,
/// acknowledgement 0, slpp-MessageBody 1, nonCriticalExtension 0, giving
/// `0100010`. Then transactionID (0..255) `00000001` | endTransaction FALSE
/// `0` | MessageBody CHOICE{c1, messageClassExtension} `0` | c1 index 0 of 16
/// `0000` | criticalExtensions index 0 of 2 `0` | RequestCapabilities-IEs opts,
/// with only sl-RTT (4th of 8) present: `00010000` | len 1 `00000001` |
/// contents: SL-RTT-RequestCapabilities `SEQUENCE {...}` is `ext 0`, 1 bit,
/// padded to an octet (§6.1) `00000000`.
///
/// That is 46 bits, plus 2 pad bits.
const REQUEST_CAPABILITIES: [u8; 6] = [0x44, 0x02, 0x00, 0x40, 0x04, 0x00];

/// SL-RTT-ProvideCapabilities as an IE (basic production):
/// ext 0 | opts (5) `00000` | positioningModes BIT STRING SIZE(1..8):
/// length-1 in 3 bits `001`, bits `01` (sl-TargetUE-Assisted only) |
/// sl-RTT-CapabilityBandList SIZE(1..nrMaxBands = 1024): count-1 in 10 bits
/// `0000000000` | SL-RTT-CapabilityPerBand ext 0, opts (3) `100`,
/// sl-PRS-RxTxTimeDiffWithoutTxTimeStamp {n1..n4} = n2 `01`.
///
/// That is 27 bits, plus 5 pad bits.
const SL_RTT_PROVIDE_CAPABILITIES: [u8; 4] = [0x00, 0xA0, 0x02, 0x20];

/// ProvideCapabilities from the UE, transaction 1, endTransaction TRUE:
/// opts `1100010` | applicationLayerID len 3 `00000011`, A5 A5 A5 |
/// transactionID `00000001` | endTransaction `1` | c1 `0` | index 1
/// `0001` | critExt `0` | IEs opts `00010000` | len 4 | the four octets of
/// [`SL_RTT_PROVIDE_CAPABILITIES`].
///
/// That is 102 bits, plus 2 pad bits.
const PROVIDE_CAPABILITIES: [u8; 13] = [
    0xC4, 0x07, 0x4B, 0x4B, 0x4A, 0x03, 0x08, 0x40, 0x10, 0x02, 0x80, 0x08, 0x80,
];

/// CommonIEsRequestLocationInformation: ext 0 | opts (7) `0000000` |
/// locationInformationType, 32 root values in 5 bits:
/// rangeMeasurementsRequired is index 5, `00101`. That is 13 bits.
const COMMON_REQUEST_LOCATION_INFORMATION: [u8; 2] = [0x00, 0x28];

/// SL-RTT-RequestLocationInformation: ext 0 | opts (9) `001000000`, with
/// only sl-PRS-RSRP-Request present | ENUMERATED {true} has one value, so it
/// takes 0 bits (§14.2). That is 10 bits.
const SL_RTT_REQUEST_LOCATION_INFORMATION: [u8; 2] = [0x10, 0x00];

/// RequestLocationInformation from the LMF, transaction 2:
/// opts `0100010` | tid `00000010` | end `0` | c1 `0` | index 4 `0100` |
/// critExt `0` | IEs opts `10010000` (common, sl-RTT) | len 2 + the common
/// IE | len 2 + the SL-RTT IE.
///
/// That is 78 bits, plus 2 pad bits.
const REQUEST_LOCATION_INFORMATION: [u8; 10] =
    [0x44, 0x04, 0x22, 0x40, 0x08, 0x00, 0xA0, 0x08, 0x40, 0x00];

/// The reported SL Rx-Tx value: TS 38.133 table 10.4A.4.1.1-1 (k = 2, so a
/// step of 4 Tc) maps 246338 to 324 <= T < 328 Tc. That is about 166.8 ns, the
/// one-way flight time over 50 m.
const RX_TX_K2: u32 = 246_338;
/// SL PRS-RSRP report value.
const RSRP: u8 = 80;

/// SL-RTT-ProvideLocationInformation:
/// ext 0 | opts `10` | SL-RTT-SignalMeasurementInformation ext 0 |
/// sl-RTT-MeasList SIZE(1..maxNrOfUEs = 256): count-1 in 8 bits `00000000` |
/// SL-RTT-MeasElementPerARP-ID-Rx SIZE(1..4): count-1 `00` |
/// SL-RTT-MeasElement ext 0, opts (3) `100`, applicationLayerID len 3 +
/// 5A 5A 5A | SL-PRS-RxTxTimeDiffMeasResult ext 0, single (index 0 of 2)
/// `0` | SL-PRS-RxTxTimeDiffResult ext 0, opts (8) `01100000` | the CHOICE of
/// 6 arms in 3 bits, k2 `010` | INTEGER (0..492513) in 19 bits, 246338 |
/// sl-PRS-RSRP-Result (0..126) in 7 bits, 80.
///
/// That is 90 bits, plus 6 pad bits.
const SL_RTT_PROVIDE_LOCATION_INFORMATION: [u8; 12] = [
    0x40, 0x01, 0x00, 0xD6, 0x96, 0x96, 0x83, 0x02, 0x78, 0x48, 0x54, 0x00,
];

/// ProvideLocationInformation from the UE, transaction 2, endTransaction TRUE:
/// opts `1100010` | applicationLayerID len 3 + A5 A5 A5 | tid `00000010` |
/// end `1` | c1 `0` | index 5 `0101` | critExt `0` | IEs opts `00010000` |
/// len 12 + [`SL_RTT_PROVIDE_LOCATION_INFORMATION`].
///
/// That is 166 bits, plus 2 pad bits.
const PROVIDE_LOCATION_INFORMATION: [u8; 21] = [
    0xC4, 0x07, 0x4B, 0x4B, 0x4A, 0x05, 0x28, 0x40, 0x31, 0x00, 0x04, 0x03, 0x5A, 0x5A, 0x5A, 0x0C,
    0x09, 0xE1, 0x21, 0x50, 0x00,
];

fn header(app_id: Option<&[u8]>, tid: u8, end: bool, body: SLPP_MessageBody_c1) -> SLPP_Message {
    SLPP_Message {
        application_layer_id: app_id.map(|a| SLPP_MessageApplicationLayerID(a.to_vec())),
        transaction_id: Some(SLPP_MessageTransactionID(tid)),
        end_transaction: SLPP_MessageEndTransaction(end),
        sequence_number: None,
        session_id: None,
        acknowledgement: None,
        slpp_message_body: Some(SLPP_MessageBody::C1(body)),
        non_critical_extension: None,
    }
}

fn body_of(msg: &SLPP_Message) -> &SLPP_MessageBody_c1 {
    match msg.slpp_message_body.as_ref().expect("a body") {
        SLPP_MessageBody::C1(c1) => c1,
        other => panic!("not c1: {other:?}"),
    }
}

// -- RequestCapabilities ----------------------------------------------------

fn request_capabilities_value() -> SLPP_Message {
    let ies = RequestCapabilities_IEs {
        common_i_es_request_capabilities: None,
        common_sl_prs_methods_i_es_request_capabilities: None,
        sl_ao_a_request_capabilities: None,
        sl_rtt_request_capabilities: Some(RequestCapabilities_IEsSl_RTT_RequestCapabilities(
            encode_ie(&SL_RTT_RequestCapabilities {}).expect("encodes"),
        )),
        sl_tdoa_request_capabilities: None,
        sl_toa_request_capabilities: None,
        late_non_critical_extension: None,
        non_critical_extension: None,
    };
    header(
        None,
        1,
        false,
        SLPP_MessageBody_c1::RequestCapabilities(RequestCapabilities {
            critical_extensions: RequestCapabilitiesCriticalExtensions::RequestCapabilities(ies),
        }),
    )
}

#[test]
fn request_capabilities_encodes_to_the_hand_derived_octets() {
    assert_eq!(
        encode(&request_capabilities_value()).expect("encodes"),
        REQUEST_CAPABILITIES
    );
}

#[test]
fn request_capabilities_decodes_field_by_field() {
    let msg = decode(&REQUEST_CAPABILITIES).expect("decodes");
    // Canonical: the decoded value re-encodes to the same octets, pad bits
    // included, which a field-by-field compare cannot see (X.691 §10.1.3
    // pads with zeros).
    assert_eq!(encode(&msg).expect("re-encodes"), REQUEST_CAPABILITIES);
    assert_eq!(msg.application_layer_id, None);
    assert_eq!(msg.transaction_id, Some(SLPP_MessageTransactionID(1)));
    assert!(!msg.end_transaction.0);
    let SLPP_MessageBody_c1::RequestCapabilities(rc) = body_of(&msg) else {
        panic!("not RequestCapabilities");
    };
    let RequestCapabilitiesCriticalExtensions::RequestCapabilities(ies) = &rc.critical_extensions
    else {
        panic!("criticalExtensionsFuture");
    };
    assert!(ies.common_i_es_request_capabilities.is_none());
    assert!(ies.sl_ao_a_request_capabilities.is_none());
    assert!(ies.sl_tdoa_request_capabilities.is_none());
    assert!(ies.sl_toa_request_capabilities.is_none());
    let container = ies.sl_rtt_request_capabilities.as_ref().expect("sl-RTT");
    assert_eq!(container.0, [0x00]);
    let _: SL_RTT_RequestCapabilities = decode_ie(&container.0).expect("inner decodes");
}

// -- ProvideCapabilities ----------------------------------------------------

fn sl_rtt_provide_capabilities_value() -> SL_RTT_ProvideCapabilities {
    let mut modes = bitvec::vec::BitVec::<u8, bitvec::order::Msb0>::new();
    modes.push(false); // sl-TargetUE-Based (0)
    modes.push(true); // sl-TargetUE-Assisted (1)
    SL_RTT_ProvideCapabilities {
        positioning_modes: PositioningModes(modes),
        ten_ms_unit_response_time: None,
        periodical_reporting: None,
        scheduled_location_request_supported: None,
        location_coordinate_types: None,
        velocity_types: None,
        sl_rtt_capability_band_list: SL_RTT_ProvideCapabilitiesSl_RTT_CapabilityBandList(vec![
            SL_RTT_CapabilityPerBand {
                sl_prs_rx_tx_time_diff_without_tx_time_stamp: Some(
                    SL_RTT_CapabilityPerBandSl_PRS_RxTxTimeDiffWithoutTxTimeStamp(1),
                ),
                sl_prs_rx_tx_time_diff_with_tx_time_stamp: None,
                dummy: None,
                extensions: SL_RTT_CapabilityPerBand_ExtAdditions {
                    measurements_for_multiple_arp_i_ds_rx: None,
                    freq_band_indicator_nr: None,
                },
            },
        ]),
    }
}

#[test]
fn sl_rtt_provide_capabilities_ie_matches_x691() {
    assert_eq!(
        encode_ie(&sl_rtt_provide_capabilities_value()).expect("encodes"),
        SL_RTT_PROVIDE_CAPABILITIES
    );
    let caps: SL_RTT_ProvideCapabilities =
        decode_ie(&SL_RTT_PROVIDE_CAPABILITIES).expect("decodes");
    assert_eq!(caps.positioning_modes.0.len(), 2);
    assert!(!caps.positioning_modes.0[0], "sl-TargetUE-Based");
    assert!(caps.positioning_modes.0[1], "sl-TargetUE-Assisted");
    assert!(caps.ten_ms_unit_response_time.is_none());
    assert!(caps.location_coordinate_types.is_none());
    assert_eq!(caps.sl_rtt_capability_band_list.0.len(), 1);
    let band = &caps.sl_rtt_capability_band_list.0[0];
    assert_eq!(
        band.sl_prs_rx_tx_time_diff_without_tx_time_stamp,
        Some(SL_RTT_CapabilityPerBandSl_PRS_RxTxTimeDiffWithoutTxTimeStamp(1)),
        "n2"
    );
    assert!(band.sl_prs_rx_tx_time_diff_with_tx_time_stamp.is_none());
    assert!(band.extensions.freq_band_indicator_nr.is_none());
}

fn provide_capabilities_value() -> SLPP_Message {
    let ies = ProvideCapabilities_IEs {
        common_i_es_provide_capabilities: None,
        common_sl_prs_methods_i_es_provide_capabilities: None,
        sl_ao_a_provide_capabilities: None,
        sl_rtt_provide_capabilities: Some(ProvideCapabilities_IEsSl_RTT_ProvideCapabilities(
            SL_RTT_PROVIDE_CAPABILITIES.to_vec(),
        )),
        sl_tdoa_provide_capabilities: None,
        sl_toa_provide_capabilities: None,
        late_non_critical_extension: None,
        non_critical_extension: None,
    };
    header(
        Some(&UE_APP_ID),
        1,
        true,
        SLPP_MessageBody_c1::ProvideCapabilities(ProvideCapabilities {
            critical_extensions: ProvideCapabilitiesCriticalExtensions::ProvideCapabilities(ies),
        }),
    )
}

#[test]
fn provide_capabilities_encodes_to_the_hand_derived_octets() {
    assert_eq!(
        encode(&provide_capabilities_value()).expect("encodes"),
        PROVIDE_CAPABILITIES
    );
}

#[test]
fn provide_capabilities_decodes_field_by_field() {
    let msg = decode(&PROVIDE_CAPABILITIES).expect("decodes");
    // Canonical: the decoded value re-encodes to the same octets, pad bits
    // included, which a field-by-field compare cannot see (X.691 §10.1.3
    // pads with zeros).
    assert_eq!(encode(&msg).expect("re-encodes"), PROVIDE_CAPABILITIES);
    assert_eq!(
        msg.application_layer_id,
        Some(SLPP_MessageApplicationLayerID(UE_APP_ID.to_vec()))
    );
    assert_eq!(msg.transaction_id, Some(SLPP_MessageTransactionID(1)));
    assert!(msg.end_transaction.0);
    let SLPP_MessageBody_c1::ProvideCapabilities(pc) = body_of(&msg) else {
        panic!("not ProvideCapabilities");
    };
    let ProvideCapabilitiesCriticalExtensions::ProvideCapabilities(ies) = &pc.critical_extensions
    else {
        panic!("criticalExtensionsFuture");
    };
    assert_eq!(
        ies.sl_rtt_provide_capabilities.as_ref().expect("sl-RTT").0,
        SL_RTT_PROVIDE_CAPABILITIES
    );
    assert!(ies.common_i_es_provide_capabilities.is_none());
}

// -- RequestLocationInformation ---------------------------------------------

fn request_location_information_value() -> SLPP_Message {
    let common = CommonIEsRequestLocationInformation {
        location_information_type: LocationInformationType(5),
        periodical_reporting: None,
        additional_information: None,
        qos: None,
        environment: None,
        scheduled_location_time: None,
        location_coordinate_types: None,
        velocity_types: None,
    };
    let rtt = SL_RTT_RequestLocationInformation {
        sl_arp_info_request: None,
        sl_los_nlos_indicator_request: None,
        sl_prs_rsrp_request: Some(SL_RTT_RequestLocationInformationSl_PRS_RSRP_Request(0)),
        sl_rsrpp_request: None,
        sl_additional_paths_request: None,
        dummy: None,
        multiple_sl_prs_rx_tx_time_diff_request: None,
        measurements_for_multiple_arp_i_ds_rx: None,
        associated_sl_prs_tx_time_stamp_request: None,
    };
    let ies = RequestLocationInformation_IEs {
        common_i_es_request_location_information: Some(
            RequestLocationInformation_IEsCommonIEsRequestLocationInformation(
                encode_ie(&common).expect("encodes"),
            ),
        ),
        common_sl_prs_methods_i_es_request_location_information: None,
        sl_ao_a_request_location_information: None,
        sl_rtt_request_location_information: Some(
            RequestLocationInformation_IEsSl_RTT_RequestLocationInformation(
                encode_ie(&rtt).expect("encodes"),
            ),
        ),
        sl_tdoa_request_location_information: None,
        sl_toa_request_location_information: None,
        late_non_critical_extension: None,
        non_critical_extension: None,
    };
    header(
        None,
        2,
        false,
        SLPP_MessageBody_c1::RequestLocationInformation(RequestLocationInformation {
            critical_extensions:
                RequestLocationInformationCriticalExtensions::RequestLocationInformation(ies),
        }),
    )
}

#[test]
fn request_location_information_encodes_to_the_hand_derived_octets() {
    let msg = request_location_information_value();
    let SLPP_MessageBody_c1::RequestLocationInformation(r) = body_of(&msg) else {
        unreachable!()
    };
    let RequestLocationInformationCriticalExtensions::RequestLocationInformation(ies) =
        &r.critical_extensions
    else {
        unreachable!()
    };
    assert_eq!(
        ies.common_i_es_request_location_information
            .as_ref()
            .unwrap()
            .0,
        COMMON_REQUEST_LOCATION_INFORMATION
    );
    assert_eq!(
        ies.sl_rtt_request_location_information.as_ref().unwrap().0,
        SL_RTT_REQUEST_LOCATION_INFORMATION
    );
    assert_eq!(encode(&msg).expect("encodes"), REQUEST_LOCATION_INFORMATION);
}

#[test]
fn request_location_information_decodes_field_by_field() {
    let msg = decode(&REQUEST_LOCATION_INFORMATION).expect("decodes");
    // Canonical: the decoded value re-encodes to the same octets, pad bits
    // included, which a field-by-field compare cannot see (X.691 §10.1.3
    // pads with zeros).
    assert_eq!(
        encode(&msg).expect("re-encodes"),
        REQUEST_LOCATION_INFORMATION
    );
    assert_eq!(msg.transaction_id, Some(SLPP_MessageTransactionID(2)));
    assert!(!msg.end_transaction.0);
    let SLPP_MessageBody_c1::RequestLocationInformation(r) = body_of(&msg) else {
        panic!("not RequestLocationInformation");
    };
    let RequestLocationInformationCriticalExtensions::RequestLocationInformation(ies) =
        &r.critical_extensions
    else {
        panic!("criticalExtensionsFuture");
    };
    // The containers are compared whole as well: decoding a container reads
    // its value bits and ignores its pad bits, so a corrupted pad octet would
    // otherwise decode to the same fields.
    assert_eq!(
        ies.common_i_es_request_location_information
            .as_ref()
            .expect("common")
            .0,
        COMMON_REQUEST_LOCATION_INFORMATION
    );
    assert_eq!(
        ies.sl_rtt_request_location_information
            .as_ref()
            .expect("sl-RTT")
            .0,
        SL_RTT_REQUEST_LOCATION_INFORMATION
    );
    let common: CommonIEsRequestLocationInformation = decode_ie(
        &ies.common_i_es_request_location_information
            .as_ref()
            .expect("common")
            .0,
    )
    .expect("common decodes");
    assert_eq!(
        common.location_information_type,
        LocationInformationType(5),
        "rangeMeasurementsRequired"
    );
    assert!(common.periodical_reporting.is_none());
    assert!(common.qos.is_none());
    let rtt: SL_RTT_RequestLocationInformation = decode_ie(
        &ies.sl_rtt_request_location_information
            .as_ref()
            .expect("sl-RTT")
            .0,
    )
    .expect("sl-RTT decodes");
    assert_eq!(
        rtt.sl_prs_rsrp_request,
        Some(SL_RTT_RequestLocationInformationSl_PRS_RSRP_Request(0))
    );
    assert!(rtt.sl_los_nlos_indicator_request.is_none());
    assert!(rtt.multiple_sl_prs_rx_tx_time_diff_request.is_none());
}

// -- ProvideLocationInformation ---------------------------------------------

fn sl_rtt_provide_location_information_value() -> SL_RTT_ProvideLocationInformation {
    let element = SL_RTT_MeasElement {
        application_layer_id: Some(SL_RTT_MeasElementApplicationLayerID(PEER_APP_ID.to_vec())),
        los_nlos_indicator: None,
        sl_pos_arp_id_rx: None,
        sl_prs_rx_tx_time_diff_meas_result:
            SL_PRS_RxTxTimeDiffMeasResult::Single_SL_PRS_RxTxTimeDiff(SL_PRS_RxTxTimeDiffResult {
                sl_prs_resource_id: None,
                sl_prs_rx_tx_time_diff_result: Some(
                    SL_PRS_RxTxTimeDiffResultSl_PRS_RxTxTimeDiffResult::K2(
                        SL_PRS_RxTxTimeDiffResultSl_PRS_RxTxTimeDiffResult_k2(RX_TX_K2),
                    ),
                ),
                sl_prs_rsrp_result: Some(SL_PRS_RxTxTimeDiffResultSl_PRS_RSRP_Result(RSRP)),
                sl_prs_rsrpp_result: None,
                sl_rtt_additional_path_list: None,
                sl_time_stamp: None,
                sl_timing_quality: None,
                tx_time_info: None,
            }),
    };
    SL_RTT_ProvideLocationInformation {
        sl_rtt_signal_measurement_information: Some(SL_RTT_SignalMeasurementInformation {
            sl_rtt_meas_list: SL_RTT_SignalMeasurementInformationSl_RTT_MeasList(vec![
                SL_RTT_MeasElementPerARP_ID_Rx(vec![element]),
            ]),
        }),
        sl_rtt_error: None,
    }
}

#[test]
fn sl_rtt_provide_location_information_ie_matches_x691() {
    assert_eq!(
        encode_ie(&sl_rtt_provide_location_information_value()).expect("encodes"),
        SL_RTT_PROVIDE_LOCATION_INFORMATION
    );
    let info: SL_RTT_ProvideLocationInformation =
        decode_ie(&SL_RTT_PROVIDE_LOCATION_INFORMATION).expect("decodes");
    assert!(info.sl_rtt_error.is_none());
    let list = &info
        .sl_rtt_signal_measurement_information
        .expect("measurements")
        .sl_rtt_meas_list
        .0;
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].0.len(), 1);
    let element = &list[0].0[0];
    assert_eq!(
        element.application_layer_id,
        Some(SL_RTT_MeasElementApplicationLayerID(PEER_APP_ID.to_vec()))
    );
    assert!(element.los_nlos_indicator.is_none());
    assert!(element.sl_pos_arp_id_rx.is_none());
    let SL_PRS_RxTxTimeDiffMeasResult::Single_SL_PRS_RxTxTimeDiff(result) =
        &element.sl_prs_rx_tx_time_diff_meas_result
    else {
        panic!("not single");
    };
    assert!(result.sl_prs_resource_id.is_none());
    assert_eq!(
        result.sl_prs_rx_tx_time_diff_result,
        Some(SL_PRS_RxTxTimeDiffResultSl_PRS_RxTxTimeDiffResult::K2(
            SL_PRS_RxTxTimeDiffResultSl_PRS_RxTxTimeDiffResult_k2(RX_TX_K2)
        ))
    );
    assert_eq!(
        result.sl_prs_rsrp_result,
        Some(SL_PRS_RxTxTimeDiffResultSl_PRS_RSRP_Result(RSRP))
    );
    assert!(result.sl_time_stamp.is_none());
    assert!(result.tx_time_info.is_none());
}

fn provide_location_information_value() -> SLPP_Message {
    let ies = ProvideLocationInformation_IEs {
        common_i_es_provide_location_information: None,
        common_sl_prs_methods_i_es_provide_location_information: None,
        sl_ao_a_provide_location_information: None,
        sl_rtt_provide_location_information: Some(
            ProvideLocationInformation_IEsSl_RTT_ProvideLocationInformation(
                encode_ie(&sl_rtt_provide_location_information_value()).expect("encodes"),
            ),
        ),
        sl_tdoa_provide_location_information: None,
        sl_toa_provide_location_information: None,
        late_non_critical_extension: None,
        non_critical_extension: None,
    };
    header(
        Some(&UE_APP_ID),
        2,
        true,
        SLPP_MessageBody_c1::ProvideLocationInformation(ProvideLocationInformation {
            critical_extensions:
                ProvideLocationInformationCriticalExtensions::ProvideLocationInformation(ies),
        }),
    )
}

#[test]
fn provide_location_information_encodes_to_the_hand_derived_octets() {
    assert_eq!(
        encode(&provide_location_information_value()).expect("encodes"),
        PROVIDE_LOCATION_INFORMATION
    );
}

#[test]
fn provide_location_information_decodes_field_by_field() {
    let msg = decode(&PROVIDE_LOCATION_INFORMATION).expect("decodes");
    // Canonical: the decoded value re-encodes to the same octets, pad bits
    // included, which a field-by-field compare cannot see (X.691 §10.1.3
    // pads with zeros).
    assert_eq!(
        encode(&msg).expect("re-encodes"),
        PROVIDE_LOCATION_INFORMATION
    );
    assert_eq!(
        msg.application_layer_id,
        Some(SLPP_MessageApplicationLayerID(UE_APP_ID.to_vec()))
    );
    assert_eq!(msg.transaction_id, Some(SLPP_MessageTransactionID(2)));
    assert!(msg.end_transaction.0);
    assert!(msg.sequence_number.is_none());
    assert!(msg.acknowledgement.is_none());
    let SLPP_MessageBody_c1::ProvideLocationInformation(p) = body_of(&msg) else {
        panic!("not ProvideLocationInformation");
    };
    let ProvideLocationInformationCriticalExtensions::ProvideLocationInformation(ies) =
        &p.critical_extensions
    else {
        panic!("criticalExtensionsFuture");
    };
    assert!(ies.common_i_es_provide_location_information.is_none());
    assert_eq!(
        ies.sl_rtt_provide_location_information
            .as_ref()
            .expect("sl-RTT")
            .0,
        SL_RTT_PROVIDE_LOCATION_INFORMATION
    );
}

// -- Bounds -------------------------------------------------------------------

fn one_measurement() -> SL_RTT_MeasElementPerARP_ID_Rx {
    let full = sl_rtt_provide_location_information_value();
    full.sl_rtt_signal_measurement_information
        .expect("measurements")
        .sl_rtt_meas_list
        .0[0]
        .clone()
}

/// `SIZE (1..maxNrOfUEs)` resolves to 1..256 through the merged module (the
/// constant lives in SLPP-PDU-Definitions, the list in the SL-RTT contents),
/// so the count takes 8 bits. 256 elements must encode, and 257 must not.
#[test]
fn the_meas_list_holds_exactly_max_nr_of_ues() {
    let with = |n: usize| SL_RTT_ProvideLocationInformation {
        sl_rtt_signal_measurement_information: Some(SL_RTT_SignalMeasurementInformation {
            sl_rtt_meas_list: SL_RTT_SignalMeasurementInformationSl_RTT_MeasList(vec![
                one_measurement();
                n
            ]),
        }),
        sl_rtt_error: None,
    };
    let at_bound = encode_ie(&with(256)).expect("256 = maxNrOfUEs encodes");
    // ext 0 | opts 10 | ext 0 | count-1 = 255 in 8 bits.
    assert_eq!(at_bound[0], 0b0100_1111, "count field is 8 bits wide");
    assert_eq!(at_bound[1] >> 4, 0b1111);
    let back: SL_RTT_ProvideLocationInformation = decode_ie(&at_bound).expect("decodes");
    assert_eq!(
        back.sl_rtt_signal_measurement_information
            .expect("measurements")
            .sl_rtt_meas_list
            .0
            .len(),
        256
    );
    assert!(encode_ie(&with(257)).is_err(), "257 > maxNrOfUEs");
    assert!(encode_ie(&with(0)).is_err(), "SIZE lower bound is 1");
}

/// An empty basic production becomes one zero octet (X.691 §10.1.3).
#[test]
fn an_empty_encoding_is_one_zero_octet() {
    assert_eq!(
        encode_ie(&SLPP_MessageNonCriticalExtension {}).expect("encodes"),
        [0x00]
    );
}
