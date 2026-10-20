//! Cross-codec checks: every NRPPa PDU lmfd builds with the hand-written
//! `nextgcore-asn1c::nrppa` codec must decode under this generated codec and
//! re-encode to the same octets, and hand-derived X.691 octets pin both.

use super::*;
use nextgcore_asn1c::nrppa::ies::{
    ECidMeasurementResult, MeasurementPeriodicity, MeasurementQuantities,
    MeasurementQuantitiesItem, MeasurementQuantitiesValue, NgRanAccessPointPosition, NgRanCell,
    NgRanCgi, PlmnIdentity, ReportCharacteristics, Tac, UeMeasurementId,
};
use nextgcore_asn1c::nrppa::pdu::{
    build_ecid_measurement_initiation_request, build_ecid_measurement_report,
    build_trp_information_request, build_trp_information_response,
};
use nextgcore_asn1c::nrppa::trp::{
    GeographicalCoordinates, TrpId, TrpInformation, TrpInformationTypeItem,
    TrpInformationTypeResponseItem, TrpInformationTypeResponseList, TrpPositionDefinitionType,
    TrpPositionDirect, TrpPositionDirectAccuracy,
};
use nextgcore_asn1c::nrppa::types::NrppaTransactionId;

/// Decode `bytes` with the generated codec and re-encode; the octets must not move.
fn assert_round_trips(label: &str, bytes: &[u8]) -> NRPPA_PDU {
    let pdu = decode(bytes).unwrap_or_else(|e| panic!("{label}: generated decode failed: {e:?}"));
    let again = encode(&pdu).unwrap_or_else(|e| panic!("{label}: generated encode failed: {e:?}"));
    assert_eq!(
        again, bytes,
        "{label}: generated re-encode differs from the hand-written octets"
    );
    pdu
}

fn rsrp() -> MeasurementQuantities {
    MeasurementQuantities {
        items: vec![MeasurementQuantitiesItem {
            measurement_quantities_value: MeasurementQuantitiesValue::Rsrp,
        }],
    }
}

/// TS 38.455 E-CIDMeasurementInitiationRequest, derived by hand from X.691:
///
/// ```text
/// 00          NRPPA-PDU CHOICE: ext 0, index 0 (initiatingMessage), pad
/// 02          procedureCode 2 (id-e-CIDMeasurementInitiation), 1-octet aligned
/// 00          criticality reject (2 bits), pad
/// 00 07       nrppatransactionID 7, INTEGER (0..32767) 2-octet aligned
/// 1c          open type length 28
///  00 00 04   SEQUENCE ext 0 + pad; ProtocolIE-Container count 4 (16 bits)
///  00 02 00 01 10      id 2 LMF-UE-Measurement-ID, reject; INTEGER (1..15, ...) ext 0, 3-1 in 4 bits
///  00 03 00 01 40      id 3 ReportCharacteristics, reject; ext 0, periodic (1 bit)
///  00 04 00 01 20      id 4 MeasurementPeriodicity, reject; ext 0, ms1024 = 4 of 13 (4 bits)
///  00 05 00 06         id 5 MeasurementQuantities, reject; 6 octets:
///     00 00 0b 00 01 10    SIZE(1..64) count-1 = 0 (6 bits) + pad; id 11, reject;
///                          Item: ext 0, iE-Extensions absent, rSRP = 4 of 6 (3 bits)
/// ```
const ECID_INITIATION_REQUEST: [u8; 34] = [
    0x00, 0x02, 0x00, 0x00, 0x07, 0x1c, 0x00, 0x00, 0x04, 0x00, 0x02, 0x00, 0x01, 0x10, 0x00, 0x03,
    0x00, 0x01, 0x40, 0x00, 0x04, 0x00, 0x01, 0x20, 0x00, 0x05, 0x00, 0x06, 0x00, 0x00, 0x0b, 0x00,
    0x01, 0x10,
];

#[test]
fn ecid_measurement_initiation_request_matches_x691_in_both_codecs() {
    let hand = build_ecid_measurement_initiation_request(
        NrppaTransactionId(7),
        UeMeasurementId(3),
        ReportCharacteristics::Periodic,
        Some(MeasurementPeriodicity::Ms1024),
        &rsrp(),
    )
    .unwrap()
    .encode()
    .unwrap();
    assert_eq!(
        &hand[..],
        &ECID_INITIATION_REQUEST[..],
        "hand-written codec"
    );
    assert_round_trips("E-CID initiation request", &ECID_INITIATION_REQUEST);
}

#[test]
fn ecid_measurement_initiation_request_variants_agree() {
    let periodicities = [
        None,
        Some(MeasurementPeriodicity::Ms120),
        Some(MeasurementPeriodicity::Ms1024),
        Some(MeasurementPeriodicity::Min60),
    ];
    for tx in [0u16, 1, 255, 256, 32767] {
        for meas in [1u16, 15] {
            for &per in &periodicities {
                for rc in [
                    ReportCharacteristics::OnDemand,
                    ReportCharacteristics::Periodic,
                ] {
                    let hand = build_ecid_measurement_initiation_request(
                        NrppaTransactionId(tx),
                        UeMeasurementId(meas),
                        rc,
                        per,
                        &rsrp(),
                    )
                    .unwrap()
                    .encode()
                    .unwrap();
                    assert_round_trips(&format!("tx {tx} meas {meas} {per:?} {rc:?}"), &hand);
                }
            }
        }
    }
}

fn sample_result(cell: u64) -> ECidMeasurementResult {
    ECidMeasurementResult {
        serving_cell_id: NgRanCgi {
            plmn_identity: PlmnIdentity([0x99, 0xf9, 0x07]),
            ng_ran_cell: NgRanCell::NrCellId(cell),
        },
        serving_cell_tac: Tac::from_u24(7),
        ng_ran_access_point_position: None,
        measured_results: None,
    }
}

#[test]
fn ecid_measurement_report_agrees() {
    for cell in [0u64, 1, 0x1_2345_6789, (1u64 << 36) - 1] {
        let hand = build_ecid_measurement_report(
            NrppaTransactionId(9),
            UeMeasurementId(3),
            UeMeasurementId(5),
            &sample_result(cell),
            None,
        )
        .unwrap()
        .encode()
        .unwrap();
        assert_round_trips(&format!("E-CID report cell {cell:#x}"), &hand);
    }
}

#[test]
fn trp_information_request_agrees() {
    let types = vec![
        TrpInformationTypeItem::NrPci,
        TrpInformationTypeItem::Arfcn,
        TrpInformationTypeItem::GeoCoord,
    ];
    for trps in [
        None,
        Some(vec![TrpId(1)]),
        Some(vec![TrpId(1), TrpId(2), TrpId(65535)]),
    ] {
        let hand =
            build_trp_information_request(NrppaTransactionId(3), trps.clone(), types.clone())
                .unwrap()
                .encode()
                .unwrap();
        assert_round_trips(&format!("TRP request {trps:?}"), &hand);
    }
}

#[test]
fn trp_information_response_agrees() {
    let position = NgRanAccessPointPosition {
        latitude_sign_south: true,
        latitude: 8_388_607,
        longitude: -8_388_608,
        direction_of_altitude_depth: true,
        altitude: 32_767,
        uncertainty_semi_major: 127,
        uncertainty_semi_minor: 0,
        orientation_of_major_axis: 179,
        uncertainty_altitude: 1,
        confidence: 100,
    };
    let info = |id: u16| TrpInformation {
        trp_id: TrpId(id),
        response_list: TrpInformationTypeResponseList {
            items: vec![
                TrpInformationTypeResponseItem::PciNr(1007),
                TrpInformationTypeResponseItem::Arfcn(3_279_165),
                TrpInformationTypeResponseItem::GeographicalCoordinates(GeographicalCoordinates {
                    position_definition_type: TrpPositionDefinitionType::Direct(
                        TrpPositionDirect {
                            accuracy: TrpPositionDirectAccuracy::TrpPosition(position),
                        },
                    ),
                }),
            ],
        },
    };
    let hand = build_trp_information_response(NrppaTransactionId(3), vec![info(1), info(65535)])
        .unwrap()
        .encode()
        .unwrap();
    assert_round_trips("TRP response", &hand);
}

/// TS 38.455 TRPInformationRequest (no TRPList; types nrPCI, geoCoord), derived
/// by hand from X.691:
///
/// ```text
/// 00 10 00 00 03 12   initiatingMessage, procedureCode 16, reject, transaction 3, length 18
///  00 00 01           SEQUENCE ext 0 + pad; ProtocolIE-Container count 1
///  00 1d 00 0b        id 29 TRPInformationTypeListTRPReq, reject; 11 octets:
///   04                SIZE(1..64) count-1 = 1 in 6 bits, pad
///   00 39 00 01 00    id 57 TRPInformationTypeItem, reject; ext 0, nrPCI = 0 of 8 (3 bits)
///   00 39 00 01 70    id 57, reject; ext 0, geoCoord = 7
/// ```
const TRP_INFORMATION_REQUEST: [u8; 24] = [
    0x00, 0x10, 0x00, 0x00, 0x03, 0x12, 0x00, 0x00, 0x01, 0x00, 0x1d, 0x00, 0x0b, 0x04, 0x00, 0x39,
    0x00, 0x01, 0x00, 0x00, 0x39, 0x00, 0x01, 0x70,
];

/// TS 38.455 TRPInformationResponse (one TRP, id 1, carrying pCI-NR 17):
///
/// ```text
/// 20 10 00 00 03 10   successfulOutcome (index 1), procedureCode 16, reject, transaction 3, length 16
///  00 00 01           SEQUENCE ext 0 + pad; ProtocolIE-Container count 1
///  00 1e 40 09        id 30 TRPInformationListTRPResp, ignore; 9 octets:
///   00 00             SIZE(1..65535) count-1 = 0, 2-octet aligned
///   00                item ext 0, iE-Extensions absent; TRPInformation ext 0, iE-Extensions
///                     absent; TRP-ID ext 0; pad
///   00 00             TRP-ID 1 (1..65535), 2-octet aligned
///   00 00             SIZE(1..64) count-1 = 0 (6 bits); CHOICE index 0 of 9 (4 bits); pad
///   00 11             pCI-NR 17 (0..1007), 2-octet aligned
/// ```
const TRP_INFORMATION_RESPONSE: [u8; 22] = [
    0x20, 0x10, 0x00, 0x00, 0x03, 0x10, 0x00, 0x00, 0x01, 0x00, 0x1e, 0x40, 0x09, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x11,
];

#[test]
fn trp_information_request_matches_x691_in_both_codecs() {
    let hand = build_trp_information_request(
        NrppaTransactionId(3),
        None,
        vec![
            TrpInformationTypeItem::NrPci,
            TrpInformationTypeItem::GeoCoord,
        ],
    )
    .unwrap()
    .encode()
    .unwrap();
    assert_eq!(
        &hand[..],
        &TRP_INFORMATION_REQUEST[..],
        "hand-written codec"
    );
    assert_round_trips("TRP request golden", &TRP_INFORMATION_REQUEST);
}

#[test]
fn trp_information_response_matches_x691_in_both_codecs() {
    let hand = build_trp_information_response(
        NrppaTransactionId(3),
        vec![TrpInformation {
            trp_id: TrpId(1),
            response_list: TrpInformationTypeResponseList {
                items: vec![TrpInformationTypeResponseItem::PciNr(17)],
            },
        }],
    )
    .unwrap()
    .encode()
    .unwrap();
    assert_eq!(
        &hand[..],
        &TRP_INFORMATION_RESPONSE[..],
        "hand-written codec"
    );
    assert_round_trips("TRP response golden", &TRP_INFORMATION_RESPONSE);
}
