//! Golden checks: hand-derived X.691 octets for NRPPa messages lmfd exchanges
//! decode under this generated codec and re-encode to the same octets. Until #515
//! deleted it, nextgcore-asn1c's hand-written NRPPa codec was cross-checked here
//! too; both codecs produced these octets.

use super::*;
use generated as nrppa;

/// Decode `bytes` with the generated codec and re-encode; the octets must not move.
fn assert_round_trips(label: &str, bytes: &[u8]) -> NRPPA_PDU {
    let pdu = decode(bytes).unwrap_or_else(|e| panic!("{label}: generated decode failed: {e:?}"));
    let again = encode(&pdu).unwrap_or_else(|e| panic!("{label}: generated encode failed: {e:?}"));
    assert_eq!(
        again, bytes,
        "{label}: generated re-encode differs from the golden octets"
    );
    pdu
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
fn ecid_measurement_initiation_request_matches_x691() {
    let nrppa::NRPPA_PDU::InitiatingMessage(m) =
        assert_round_trips("E-CID initiation request", &ECID_INITIATION_REQUEST)
    else {
        panic!("not an initiating message");
    };
    assert_eq!(m.procedure_code.0, nrppa::ID_E_CID_MEASUREMENT_INITIATION);
    assert_eq!(m.nrppatransaction_id.0, 7);
    let nrppa::InitiatingMessageValue::Id_e_CIDMeasurementInitiation(req) = m.value else {
        panic!("not an E-CID Measurement Initiation Request");
    };
    let ids: Vec<u16> = req.protocol_i_es.0.iter().map(|ie| ie.id.0).collect();
    assert_eq!(ids, vec![2, 3, 4, 5]);
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
fn trp_information_request_matches_x691() {
    let nrppa::NRPPA_PDU::InitiatingMessage(m) =
        assert_round_trips("TRP request golden", &TRP_INFORMATION_REQUEST)
    else {
        panic!("not an initiating message");
    };
    assert_eq!(m.procedure_code.0, nrppa::ID_T_RP_INFORMATION_EXCHANGE);
}

#[test]
fn trp_information_response_matches_x691() {
    let nrppa::NRPPA_PDU::SuccessfulOutcome(m) =
        assert_round_trips("TRP response golden", &TRP_INFORMATION_RESPONSE)
    else {
        panic!("not a successful outcome");
    };
    let nrppa::SuccessfulOutcomeValue::Id_tRPInformationExchange(resp) = m.value else {
        panic!("not a TRP Information Response");
    };
    let nrppa::TRPInformationResponseProtocolIEs_EntryValue::Id_TRPInformationListTRPResp(list) =
        &resp.protocol_i_es.0[0].value
    else {
        panic!("not the TRP information list");
    };
    let item = &list.0[0].trp_information;
    assert_eq!(item.trp_id.0, 1);
    assert!(matches!(
        &item.trp_information_type_response_list.0[0],
        nrppa::TRPInformationTypeResponseItem::PCI_NR(p) if p.0 == 17
    ));
}
