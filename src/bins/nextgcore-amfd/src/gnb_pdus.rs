//! #417 stage B3.3: the NGAP PDUs amfd's tests stand in for a gNB or a CBCF
//! with. They are octets derived by hand from the TS 38.413 V17.9 ASN.1 and
//! X.691 ALIGNED, through [`crate::aper_golden::Bits`], with the derivation
//! written beside each builder. They used to come from the hand-written
//! `nextgcore-ngap` builders.
//!
//! Each builder is pinned twice in this module's tests: by a vector worked out
//! octet by octet in the test, and by the generated codec's strict decode,
//! which has to read those octets as the PDU the builder says they are.

use crate::aper_golden::{pdu, Bits};

/// MessageIdentifier / SerialNumber `BIT STRING (SIZE(16))`: fixed, sixteen
/// bits, so as the whole IE value two octets.
fn sixteen_bits(v: u16) -> Vec<u8> {
    v.to_be_bytes().to_vec()
}

/// NR-CGI (§9.3.1.7): extension `0`, iE-Extensions `0`; PLMNIdentity
/// `OCTET STRING (SIZE(3))` aligned with no length (§17.6); NRCellIdentity
/// `BIT STRING (SIZE(36))`, fixed and longer than sixteen bits, so aligned
/// with no length (§16.10).
fn nr_cgi(b: &mut Bits, plmn: [u8; 3], nci: u64) {
    b.field(0, 2).octets(&plmn).align().field(nci, 36);
}

/// WRITE-REPLACE WARNING REQUEST (§9.2.8.1) as a CBCF sends it, with a Data
/// Coding Scheme and Warning Message Contents and no area list:
///
/// - initiatingMessage, id-WriteReplaceWarning 51, reject;
/// - id 35 MessageIdentifier, id 95 SerialNumber (reject): two octets each;
/// - id 87 RepetitionPeriod (reject): `INTEGER (0..131071)` is past 64K, so
///   the octet count n (1..3) as n-1 in two bits, padded, then n octets;
/// - id 47 NumberOfBroadcastsRequested (reject): `INTEGER (0..65535)`, range
///   65536, two aligned octets (§11.5.7.3);
/// - id 20 DataCodingScheme (ignore): `BIT STRING (SIZE(8))`, one octet;
/// - id 123 WarningMessageContents (ignore): `OCTET STRING (SIZE(1..9600))`,
///   so its length is a constrained whole number, length-1 in two aligned
///   octets (range 9600, §11.5.7.3, §17.8), then the octets.
pub(crate) fn write_replace_warning_request(
    message_identifier: u16,
    serial_number: u16,
    repetition_period: u32,
    broadcasts: u16,
    data_coding_scheme: u8,
    contents: &[u8],
) -> Vec<u8> {
    assert!((1..=9600).contains(&contents.len()));
    let repetition = crate::aper_golden::long_integer(u64::from(repetition_period), 2);
    let mut warning = Bits::default();
    warning
        .octets(&(contents.len() as u16 - 1).to_be_bytes())
        .octets(contents);
    pdu(
        0,
        51,
        0,
        &[
            (35, 0, sixteen_bits(message_identifier)),
            (95, 0, sixteen_bits(serial_number)),
            (87, 0, repetition),
            (47, 0, broadcasts.to_be_bytes().to_vec()),
            (20, 1, vec![data_coding_scheme]),
            (123, 1, warning.finish()),
        ],
    )
}

/// PWS CANCEL REQUEST (§9.2.8.3), no area list: initiatingMessage, id-PWSCancel
/// 32, reject; ids 35 and 95 as above; id 14 CancelAllWarningMessages (reject)
/// when cancelling all, `ENUMERATED {true, ...}`, one extension bit, padded `00`.
pub(crate) fn pws_cancel_request(
    message_identifier: u16,
    serial_number: u16,
    cancel_all: bool,
) -> Vec<u8> {
    let mut ies = vec![
        (35, 0, sixteen_bits(message_identifier)),
        (95, 0, sixteen_bits(serial_number)),
    ];
    if cancel_all {
        ies.push((14, 0, vec![0x00]));
    }
    pdu(0, 32, 0, &ies)
}

/// PWS FAILURE INDICATION (§9.2.8.6) from a gNB, one failed NR cell:
///
/// - initiatingMessage, id-PWSFailureIndication 33, ignore;
/// - id 81 PWSFailedCellIDList (reject): CHOICE of three (not extensible)
///   nR-CGI-PWSFailedList `01`, padded; NR-CGIList `SIZE(1..16384)`, count-1 in
///   two aligned octets (range 16384); the NR-CGI;
/// - id 27 GlobalRANNodeID (reject): CHOICE of four globalGNB-ID `00`;
///   GlobalGNB-ID extension `0`, iE-Extensions `0`; the PLMN; GNB-ID CHOICE of
///   two gNB-ID `0`; `BIT STRING (SIZE(22..32))`: length-22 in four bits
///   (range 11), then the bits aligned (§16.11). The gNB ID is the low
///   `gnb_id_len` bits of `gnb_id`.
pub(crate) fn pws_failure_indication(
    plmn: [u8; 3],
    failed_nci: u64,
    gnb_id: u32,
    gnb_id_len: u32,
) -> Vec<u8> {
    assert!((22..=32).contains(&gnb_id_len));
    let mut cells = Bits::default();
    cells.field(1, 2).octets(&[0x00, 0x00]);
    nr_cgi(&mut cells, plmn, failed_nci);
    let mut node = Bits::default();
    node.field(0, 2).field(0, 2).octets(&plmn);
    node.bit(false)
        .field(u64::from(gnb_id_len - 22), 4)
        .align()
        .field(u64::from(gnb_id), gnb_id_len);
    pdu(0, 33, 1, &[(81, 0, cells.finish()), (27, 0, node.finish())])
}

/// WRITE-REPLACE WARNING RESPONSE (§9.2.8.2) from a gNB:
///
/// - successfulOutcome, id-WriteReplaceWarning 51, reject; ids 35 and 95;
/// - id 13 BroadcastCompletedAreaList (ignore), when there are cells: CHOICE of
///   seven (not extensible) cellIDBroadcastNR `011`, padded; CellIDBroadcastNR
///   `SIZE(1..65535)`, count-1 in two aligned octets; per item extension `0`,
///   iE-Extensions `0`, then the NR-CGI.
pub(crate) fn write_replace_warning_response(
    message_identifier: u16,
    serial_number: u16,
    completed: Option<([u8; 3], &[u64])>,
) -> Vec<u8> {
    let mut ies = vec![
        (35, 0, sixteen_bits(message_identifier)),
        (95, 0, sixteen_bits(serial_number)),
    ];
    if let Some((plmn, cells)) = completed {
        let mut area = Bits::default();
        area.field(3, 3)
            .octets(&(cells.len() as u16 - 1).to_be_bytes());
        for &nci in cells {
            area.field(0, 2);
            nr_cgi(&mut area, plmn, nci);
        }
        ies.push((13, 1, area.finish()));
    }
    pdu(1, 51, 0, &ies)
}

#[cfg(test)]
mod tests {
    use super::*;
    use nextgcore_ngap_gen::generated as g;

    /// The IE ids of a PDU the generated codec decodes strictly, by message.
    fn ids(bytes: &[u8]) -> (u8, Vec<u16>) {
        macro_rules! ies {
            ($m:expr) => {
                $m.protocol_i_es.0.iter().map(|ie| ie.id.0).collect()
            };
        }
        match nextgcore_ngap_gen::decode(bytes).expect("strict generated decode") {
            g::NGAP_PDU::InitiatingMessage(m) => match m.value {
                g::InitiatingMessageValue::Id_WriteReplaceWarning(v) => (51, ies!(v)),
                g::InitiatingMessageValue::Id_PWSCancel(v) => (32, ies!(v)),
                g::InitiatingMessageValue::Id_PWSFailureIndication(v) => (33, ies!(v)),
                other => panic!("unexpected {other:?}"),
            },
            g::NGAP_PDU::SuccessfulOutcome(m) => match m.value {
                g::SuccessfulOutcomeValue::Id_WriteReplaceWarning(v) => (51, ies!(v)),
                other => panic!("unexpected {other:?}"),
            },
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn write_replace_warning_request_is_the_worked_octets() {
        let pdu = write_replace_warning_request(0x1234, 0x5678, 32, 3, 0x01, b"TSUNAMI");
        assert_eq!(
            pdu,
            [
                0x00, 0x33, 0x00, 0x2d, // initiatingMessage, 51, reject, length 45
                0x00, 0x00, 0x06, // six IEs
                0x00, 0x23, 0x00, 0x02, 0x12, 0x34, // MessageIdentifier
                0x00, 0x5f, 0x00, 0x02, 0x56, 0x78, // SerialNumber
                0x00, 0x57, 0x00, 0x02, 0x00, 0x20, // RepetitionPeriod: n=1 `00`, 32
                0x00, 0x2f, 0x00, 0x02, 0x00, 0x03, // NumberOfBroadcastsRequested
                0x00, 0x14, 0x40, 0x01, 0x01, // DataCodingScheme, ignore
                0x00, 0x7b, 0x40, 0x09, 0x00, 0x06, // WarningMessageContents, length-1 6
                b'T', b'S', b'U', b'N', b'A', b'M', b'I',
            ]
        );
        assert_eq!(ids(&pdu), (51, vec![35, 95, 87, 47, 20, 123]));
    }

    #[test]
    fn pws_cancel_request_is_the_worked_octets() {
        let all = pws_cancel_request(0xA396, 0xC396, true);
        assert_eq!(
            all,
            [
                0x00, 0x20, 0x00, 0x14, // initiatingMessage, 32, reject, length 20
                0x00, 0x00, 0x03, //
                0x00, 0x23, 0x00, 0x02, 0xa3, 0x96, //
                0x00, 0x5f, 0x00, 0x02, 0xc3, 0x96, //
                0x00, 0x0e, 0x00, 0x01, 0x00, // CancelAllWarningMessages true
            ]
        );
        assert_eq!(ids(&all), (32, vec![35, 95, 14]));
        assert_eq!(ids(&pws_cancel_request(1, 2, false)), (32, vec![35, 95]));
    }

    #[test]
    fn pws_failure_indication_is_the_worked_octets() {
        let pdu = pws_failure_indication([0x00, 0xF1, 0x10], 0x396, 0x396, 32);
        assert_eq!(
            pdu,
            [
                0x00, 0x21, 0x40, 0x20, // initiatingMessage, 33, ignore, length 32
                0x00, 0x00, 0x02, //
                0x00, 0x51, 0x00, 0x0c, // PWSFailedCellIDList, reject, length 12
                0x40, 0x00, 0x00, // nR-CGI-PWSFailedList `01`, count-1 0
                0x00, 0x00, 0xf1, 0x10, 0x00, 0x00, 0x00, 0x39, 0x60, // NR-CGI
                0x00, 0x1b, 0x00, 0x09, // GlobalRANNodeID, reject, length 9
                0x00, 0x00, 0xf1, 0x10, // globalGNB-ID `00`, `00`, the PLMN
                0x50, 0x00, 0x00, 0x03, 0x96, // gNB-ID `0` + length-22 `1010`, 32 bits
            ]
        );
        assert_eq!(ids(&pdu), (33, vec![81, 27]));
        // A 22-bit gNB ID: length-22 `0000`, then 22 bits padded.
        let short = pws_failure_indication([0x00, 0xF1, 0x10], 1, 0x2A_AAAA, 22);
        assert_eq!(&short[short.len() - 4..], [0x00, 0xaa, 0xaa, 0xa8]);
        assert_eq!(ids(&short), (33, vec![81, 27]));
    }

    #[test]
    fn write_replace_warning_response_is_the_worked_octets() {
        let pdu =
            write_replace_warning_response(0xE396, 0x1397, Some(([0x00, 0xF1, 0x10], &[0x399])));
        assert_eq!(
            pdu,
            [
                0x20, 0x33, 0x00, 0x1f, // successfulOutcome, 51, reject, length 31
                0x00, 0x00, 0x03, //
                0x00, 0x23, 0x00, 0x02, 0xe3, 0x96, //
                0x00, 0x5f, 0x00, 0x02, 0x13, 0x97, //
                0x00, 0x0d, 0x40, 0x0c, // BroadcastCompletedAreaList, ignore, length 12
                0x60, 0x00, 0x00, // cellIDBroadcastNR `011`, count-1 0
                0x00, 0x00, 0xf1, 0x10, 0x00, 0x00, 0x00, 0x39, 0x90, // item + NR-CGI
            ]
        );
        assert_eq!(ids(&pdu), (51, vec![35, 95, 13]));
        assert_eq!(
            ids(&write_replace_warning_response(1, 2, None)),
            (51, vec![35, 95])
        );
    }
}
