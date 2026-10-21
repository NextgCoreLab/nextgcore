use super::*;
use crate::codec_glue::decode_lpp_sidelink_ranging;

/// nextgsim's `GOLDEN_SIDELINK_RANGING_REPORT` (nextgsim #137), unchanged by #542:
/// one range of 50.00 m to peer 0xA5A5A5, carrier phase, 3 measurements.
///
/// ```text
///   report ext 0 | count-1 = 0 (5 bits) | result ext 0
///   peerLayer2Id 0xA5A5A5 (24) | rangeCm 5000 (20) | accuracyCm 1 (16)
///   method ext 0, carrierPhase 1 | measurementCount 3 (16)   = 85 bits -> 11 octets
/// ```
const GOLDEN_BODY: &[u8] = &[
    0x01, 0x4B, 0x4B, 0x4A, 0x02, 0x71, 0x00, 0x00, 0x28, 0x00, 0x18,
];

/// A whole uplink LPP-Message carrying that body in an EPDU, derived bit by bit
/// from X.691 (UPER) and TS 37.355, independently of any codec:
///
/// ```text
///   LPP-Message optional bitmap (transactionID, sequenceNumber, ack, body): 1001
///   LPP-TransactionID ext 0 | Initiator ext 0, targetDevice 1 | number 5 (8 bits)
///   endTransaction TRUE: 1
///   LPP-MessageBody c1: 0 | provideLocationInformation, index 5 of 16: 0101
///   criticalExtensions c1: 0 | c1 provideLocationInformation-r9, 0 of 4: 00
///   ProvideLocationInformation-r9-IEs ext 0 | optionals 0000 1 (only epdu)
///   EPDU-Sequence SIZE(1..16), one entry: 0000
///   EPDU-Identifier ext 0 | ePDU-Name present 1 | EPDU-ID 256 in (1..256): 1111 1111
///   EPDU-Name SIZE(1..32), 22 chars: 10101, then 22 x 7-bit ISO 646 (X.691 §30.5.3)
///   EPDU-Body OCTET STRING: length 11 (8 bits), then the 11 body octets
///                                                         = 304 bits, 38 octets
/// ```
const GOLDEN_MESSAGE: &[u8] = &[
    0x92, 0x0B, 0x28, 0x04, 0x1F, 0xFA, 0xEE, 0xCB, 0xE3, 0xA6, 0x75, 0xBC, 0xF4, 0xE4, 0xCB, 0xB3,
    0x4E, 0xED, 0x6B, 0x79, 0x61, 0xDD, 0x9F, 0x4E, 0xEC, 0xE1, 0x60, 0x29, 0x69, 0x69, 0x40, 0x4E,
    0x20, 0x00, 0x05, 0x00, 0x03, 0x00,
];

fn golden_report() -> SidelinkRangingReport {
    SidelinkRangingReport {
        results: vec![SidelinkRangingResult {
            peer_layer2_id: 0x00A5_A5A5,
            range_cm: 5_000,
            accuracy_cm: 1,
            method: SidelinkRangingMethod::CarrierPhase,
            measurement_count: 3,
        }],
    }
}

fn golden_message_value() -> lpp::LPP_Message {
    nextgcore_lpp_gen::decode(&build_message(5, &golden_report())).expect("decode")
}

#[test]
fn the_body_encodes_to_the_senders_golden_octets() {
    assert_eq!(encode_body(&golden_report()).expect("encodes"), GOLDEN_BODY);
}

#[test]
fn the_senders_golden_body_decodes_to_what_it_says() {
    assert_eq!(decode_body(GOLDEN_BODY).expect("decodes"), golden_report());
}

#[test]
fn the_generated_codec_encodes_the_hand_derived_message() {
    assert_eq!(build_message(5, &golden_report()), GOLDEN_MESSAGE);
}

#[test]
fn the_lmf_reads_the_range_from_the_hand_derived_message() {
    let (txn, ranges) = decode_lpp_sidelink_ranging(GOLDEN_MESSAGE).expect("decodes");
    assert_eq!(txn, 5);
    assert_eq!(ranges.len(), 1);
    assert_eq!(ranges[0].peer_layer2_id, 0x00A5_A5A5);
    assert!((ranges[0].range_m - 50.0).abs() < 1e-9);
    assert!((ranges[0].accuracy_m - 0.01).abs() < 1e-9);
    assert_eq!(ranges[0].method, SidelinkRangingMethod::CarrierPhase);
    assert_eq!(ranges[0].measurement_count, 3);
}

#[test]
fn an_epdu_with_our_id_but_another_name_is_not_read_as_a_range() {
    let mut msg = golden_message_value();
    let Some(lpp::LPP_MessageBody::C1(lpp::LPP_MessageBody_c1::ProvideLocationInformation(p))) =
        msg.lpp_message_body.as_mut()
    else {
        unreachable!()
    };
    let lpp::ProvideLocationInformationCriticalExtensions::C1(
        lpp::ProvideLocationInformationCriticalExtensions_c1::ProvideLocationInformation_r9(ies),
    ) = &mut p.critical_extensions
    else {
        unreachable!()
    };
    ies.epdu_provide_location_information.as_mut().unwrap().0[0]
        .epdu_identifier
        .epdu_name = Some(lpp::EPDU_Name("someone-else".to_string()));
    let bytes = nextgcore_lpp_gen::encode(&msg).expect("encodes");
    let (_, ranges) = decode_lpp_sidelink_ranging(&bytes).expect("decodes");
    assert!(
        ranges.is_empty(),
        "a foreign EPDU must not be misread as a range"
    );
}

#[test]
fn a_body_with_an_extension_bit_is_refused() {
    let mut body = GOLDEN_BODY.to_vec();
    body[0] |= 0x80;
    assert!(decode_body(&body).is_err());
}

#[test]
fn bodies_of_one_to_thirty_two_results_round_trip_and_others_are_refused() {
    for n in 1..=32u32 {
        let report = SidelinkRangingReport {
            results: (0..n)
                .map(|i| SidelinkRangingResult {
                    peer_layer2_id: 0x00FF_FFFF - i,
                    range_cm: 1_000_000 - i,
                    accuracy_cm: u16::MAX,
                    method: if i % 2 == 0 {
                        SidelinkRangingMethod::Rtt
                    } else {
                        SidelinkRangingMethod::CarrierPhase
                    },
                    measurement_count: i as u16,
                })
                .collect(),
        };
        let body = encode_body(&report).expect("encodes");
        assert_eq!(decode_body(&body).expect("decodes"), report, "n = {n}");
    }
    assert!(encode_body(&SidelinkRangingReport { results: vec![] }).is_err());
}

#[test]
fn a_truncated_body_is_an_error_not_a_panic() {
    for len in 0..GOLDEN_BODY.len() - 1 {
        assert!(decode_body(&GOLDEN_BODY[..len]).is_err(), "len {len}");
    }
}
