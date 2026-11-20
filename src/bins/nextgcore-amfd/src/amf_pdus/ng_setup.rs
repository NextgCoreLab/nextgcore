//! The non-UE-associated AMF->gNB PDUs (NG Setup Response and Failure, NG
//! Reset Acknowledge, Overload Start/Stop, Paging) and the handover answers
//! HANDOVER PREPARATION FAILURE and HANDOVER CANCEL ACKNOWLEDGE, derived by hand
//! from the V17.9.0 ASN.1 and X.691 ALIGNED. See [`crate::amf_pdus`].
//!
//! Each function takes the values on the wire, not the AMF state they come
//! from: what the AMF puts there (a fallback name, a clamp, a cut) is policy,
//! and the tests state it beside the call.

use crate::aper_golden::{amf_ue_ngap_id, pdu, ran_ue_ngap_id, Bits};
use crate::ngap_asn1::IeDiagnostic;
use crate::ngap_types as t;

/// The root of each Cause group's `ENUMERATED`, read off the V17.9 ASN.1
/// lists (§9.3.1.2): radioNetwork 45 (`unspecified` ..
/// `release-due-to-cn-detected-mobility`), transport 2, nas 4, protocol 7,
/// misc 6. All five are extensible.
const CAUSE_ROOTS: [u64; 5] = [45, 2, 4, 7, 6];

/// The fewest bits that hold an index below `n` (X.691 §11.5.7.2's bit-field).
fn width(n: u64) -> u32 {
    64 - (n - 1).leading_zeros()
}

/// A Cause (§9.3.1.2), `group` 0 radioNetwork .. 4 misc and `position` the
/// value's place in its group's ASN.1 list. Cause is a CHOICE of six (five
/// groups and choice-Extensions), not extensible: the index in three bits.
/// The group `ENUMERATED` is extensible (§11.6): a root value is extension
/// `0` and its index in the fewest bits that hold the root (radioNetwork six,
/// transport one, nas two, protocol and misc three); a value past the root is
/// extension `1` and its distance past the root as a normally small number,
/// `0` and six bits (§11.6.1, §11.8).
pub(crate) fn cause(b: &mut Bits, group: u64, position: u64) {
    let root = CAUSE_ROOTS[group as usize];
    b.field(group, 3);
    if position < root {
        b.bit(false).field(position, width(root));
    } else {
        assert!(
            position - root < 64,
            "a large extension is not derived here"
        );
        b.bit(true).bit(false).field(position - root, 6);
    }
}

/// [`cause`] as a whole IE value.
pub(crate) fn cause_value(group: u64, position: u64) -> Vec<u8> {
    let mut b = Bits::default();
    cause(&mut b, group, position);
    b.finish()
}

/// A domain Cause's (group, ASN.1 position), for the causes these tests send.
/// Each position is counted in the V17.9 list (§9.3.1.2); any other cause
/// panics so its position is counted before it is used.
pub(crate) fn cause_position(c: &t::Cause) -> (u64, u64) {
    use t::{CauseMisc as M, CauseNas as N, CauseProtocol as P, CauseRadioNetwork as R};
    match c {
        t::Cause::RadioNetwork(R::Unspecified) => (0, 0),
        t::Cause::RadioNetwork(R::HoTargetNotAllowed) => (0, 8),
        t::Cause::RadioNetwork(R::UserInactivity) => (0, 20),
        t::Cause::Transport(t::CauseTransport::TransportResourceUnavailable) => (1, 0),
        t::Cause::Nas(N::NormalRelease) => (2, 0),
        t::Cause::Protocol(P::SemanticError) => (3, 4),
        t::Cause::Misc(M::OmIntervention) => (4, 3),
        t::Cause::Misc(M::Unspecified) => (4, 5),
        other => panic!("count the ASN.1 position of {other:?} before using it"),
    }
}

/// CriticalityDiagnostics (§9.3.1.3): extension `0`; presence of
/// procedureCode, triggeringMessage, procedureCriticality, iEsCriticality-
/// Diagnostics and iE-Extensions; procedureCode `INTEGER (0..255)` one aligned
/// octet; triggeringMessage `ENUMERATED` of three, not extensible, two bits;
/// procedureCriticality two bits. CriticalityDiagnostics-IE-List
/// `SIZE(1..maxnoofErrors = 256)`: count-1 has range exactly 256, so one
/// ALIGNED octet (§11.5.7.2). Each item: extension `0`, iE-Extensions `0`,
/// iECriticality two bits, iE-ID `INTEGER (0..65535)` two aligned octets,
/// typeOfError `ENUMERATED {not-understood, missing, ...}` extension `0` and
/// one bit.
pub(crate) fn criticality_diagnostics(
    procedure: Option<(u8, u8, u8)>,
    items: &[IeDiagnostic],
) -> Vec<u8> {
    assert!((1..=256).contains(&items.len()));
    let mut b = Bits::default();
    let p = procedure.is_some();
    b.bit(false).bit(p).bit(p).bit(p).bit(true).bit(false);
    if let Some((code, triggering, criticality)) = procedure {
        b.octets(&[code])
            .field(u64::from(triggering), 2)
            .field(u64::from(criticality), 2);
    }
    b.octets(&[(items.len() - 1) as u8]);
    for d in items {
        b.field(0, 2)
            .field(u64::from(d.criticality), 2)
            .octets(&d.ie_id.to_be_bytes())
            .bit(false)
            .field(u64::from(d.type_of_error), 1);
    }
    b.finish()
}

/// AMFName `PrintableString (SIZE(1..150, ...))` (§9.3.3.21): extension `0`,
/// length-1 in an 8-bit field (range 150, not aligned); 74 characters is b = 7,
/// rounded to 8 in ALIGNED (§30.5.2); ub x 8 = 1200 bits is past 16, so the
/// characters are octet-aligned (§30.5.7) -- for every length, not only long
/// ones.
fn amf_name(name: &str) -> Vec<u8> {
    assert!((1..=150).contains(&name.len()) && name.is_ascii());
    let mut b = Bits::default();
    b.bit(false)
        .field(name.len() as u64 - 1, 8)
        .octets(name.as_bytes());
    b.finish()
}

/// One served GUAMI on the wire: PLMN, region, set, pointer.
pub(crate) type GuamiWire = ([u8; 3], u8, u16, u8);

/// One PLMNSupportItem on the wire: PLMN and its slices (SST, SD).
pub(crate) type PlmnSupportWire = ([u8; 3], Vec<(u8, Option<[u8; 3]>)>);

/// NG SETUP RESPONSE (§9.2.6.2): successfulOutcome, id-NGSetup 21, reject:
/// - id 1 AMFName (reject): [`amf_name`];
/// - id 96 ServedGUAMIList (reject): `SIZE(1..256)`, count-1 one aligned octet
///   (range 256); ServedGUAMIItem extension `0`, backupAMFName `0`,
///   iE-Extensions `0`; GUAMI extension `0`, iE-Extensions `0`; the PLMN
///   `OCTET STRING (SIZE(3))` aligned; aMFRegionID `BIT STRING (SIZE(8))`,
///   aMFSetID `(SIZE(10))`, aMFPointer `(SIZE(6))`, each fixed and at most 16
///   bits, so NOT aligned (§16.9): 24 bits that end on an octet;
/// - id 86 RelativeAMFCapacity (ignore): `INTEGER (0..255)`, one aligned octet;
/// - id 80 PLMNSupportList (reject): `SIZE(1..12)`, count-1 in four bits;
///   PLMNSupportItem extension `0`, iE-Extensions `0`, the PLMN aligned;
///   SliceSupportList `SIZE(1..1024)`: range 1024, so count-1 in two aligned
///   octets (§11.5.7.3); SliceSupportItem extension `0`, iE-Extensions `0`;
///   S-NSSAI extension `0`, sD presence, iE-Extensions `0`; SST
///   `OCTET STRING (SIZE(1))` eight bits NOT aligned (§17.6); SD
///   `(SIZE(3))` aligned;
/// - id 19 CriticalityDiagnostics (ignore) when there is something to report.
///
/// The BIT STRING fields take the low bits of the value: [`Bits::field`]
/// writes exactly `n`.
pub(crate) fn ng_setup_response(
    name: &str,
    guamis: &[GuamiWire],
    capacity: u8,
    plmns: &[PlmnSupportWire],
    diagnostics: &[IeDiagnostic],
) -> Vec<u8> {
    assert!((1..=256).contains(&guamis.len()));
    assert!((1..=12).contains(&plmns.len()));
    let mut served = Bits::default();
    served.octets(&[(guamis.len() - 1) as u8]);
    for (plmn, region, set, pointer) in guamis {
        served
            .field(0, 3)
            .field(0, 2)
            .octets(plmn)
            .field(u64::from(*region), 8)
            .field(u64::from(*set), 10)
            .field(u64::from(*pointer), 6);
    }
    let mut support = Bits::default();
    support.field(plmns.len() as u64 - 1, 4);
    for (plmn, slices) in plmns {
        assert!((1..=1024).contains(&slices.len()));
        support
            .field(0, 2)
            .octets(plmn)
            .octets(&(slices.len() as u16 - 1).to_be_bytes());
        for (sst, sd) in slices {
            support
                .field(0, 2)
                .bit(false)
                .bit(sd.is_some())
                .bit(false)
                .field(u64::from(*sst), 8);
            if let Some(sd) = sd {
                support.octets(sd);
            }
        }
    }
    let mut ies = vec![
        (1, 0, amf_name(name)),
        (96, 0, served.finish()),
        (86, 1, vec![capacity]),
        (80, 0, support.finish()),
    ];
    if !diagnostics.is_empty() {
        ies.push((19, 1, criticality_diagnostics(None, diagnostics)));
    }
    pdu(1, 21, 0, &ies)
}

/// NG SETUP FAILURE (§9.2.6.3): unsuccessfulOutcome, id-NGSetup 21, reject;
/// id 15 Cause (ignore); id 107 TimeToWait (ignore) when given:
/// `ENUMERATED {v1s, v2s, v5s, v10s, v20s, v60s, ...}`, extension `0` and
/// three bits; id 19 CriticalityDiagnostics (ignore) when there is something
/// to report.
pub(crate) fn ng_setup_failure(
    (group, position): (u64, u64),
    time_to_wait: Option<u8>,
    diagnostics: &[IeDiagnostic],
) -> Vec<u8> {
    let mut ies = vec![(15, 1, cause_value(group, position))];
    if let Some(ttw) = time_to_wait {
        assert!(ttw < 6, "TimeToWait has six root values");
        let mut b = Bits::default();
        b.bit(false).field(u64::from(ttw), 3);
        ies.push((107, 1, b.finish()));
    }
    if !diagnostics.is_empty() {
        ies.push((19, 1, criticality_diagnostics(None, diagnostics)));
    }
    pdu(2, 21, 0, &ies)
}

/// NG RESET ACKNOWLEDGE (§9.2.6.12): successfulOutcome, id-NGReset 20,
/// reject; id 111 UE-associatedLogicalNG-connectionList (ignore) for a partial
/// reset; id 19 CriticalityDiagnostics (ignore) when there is something to
/// report. The list is `SIZE(1..maxnoofNGConnectionsToReset = 65536)`: ub is
/// 64K, not below it, so the count is a general length determinant, the count
/// itself in one aligned octet below 128 (§11.9.4.2, §11.9.3.6) -- not count-1
/// in two octets. Per item extension `0`, presence of AMF-UE-NGAP-ID and
/// RAN-UE-NGAP-ID, iE-Extensions `0`; each present ID `INTEGER` past 64K: its
/// octet count-1 in three (AMF, 0..2^40-1) or two (RAN, 0..2^32-1) bits, then
/// its minimal octets aligned (§11.5.7.4).
pub(crate) fn ng_reset_acknowledge(
    connections: Option<&[t::UeAssociatedLogicalNgConnectionItem]>,
    diagnostics: &[IeDiagnostic],
) -> Vec<u8> {
    let mut ies = Vec::new();
    if let Some(items) = connections {
        assert!(
            (1..128).contains(&items.len()),
            "longer lists are not derived here"
        );
        let mut b = Bits::default();
        b.octets(&[items.len() as u8]);
        for item in items {
            b.bit(false)
                .bit(item.amf_ue_ngap_id.is_some())
                .bit(item.ran_ue_ngap_id.is_some())
                .bit(false);
            if let Some(amf) = item.amf_ue_ngap_id {
                long_integer_into(&mut b, amf, 3);
            }
            if let Some(ran) = item.ran_ue_ngap_id {
                long_integer_into(&mut b, u64::from(ran), 2);
            }
        }
        ies.push((111, 1, b.finish()));
    }
    if !diagnostics.is_empty() {
        ies.push((19, 1, criticality_diagnostics(None, diagnostics)));
    }
    pdu(1, 20, 0, &ies)
}

/// An `INTEGER` past 64K written where the sink is: octet count-1 in `width`
/// bits, unaligned, then the minimal octets aligned (§11.5.7.4).
fn long_integer_into(b: &mut Bits, value: u64, width: u32) {
    let be = value.to_be_bytes();
    let skip = be.iter().take_while(|o| **o == 0).count().min(7);
    b.field((8 - skip) as u64 - 1, width).octets(&be[skip..]);
}

/// OVERLOAD START (§9.2.6.10): initiatingMessage, id-OverloadStart 22,
/// ignore; id 9 AMFTrafficLoadReductionIndication (ignore):
/// `INTEGER (1..99)`, range 99, so value-1 in seven bits, padded.
pub(crate) fn overload_start(percent: u8) -> Vec<u8> {
    assert!((1..=99).contains(&percent));
    let mut b = Bits::default();
    b.field(u64::from(percent - 1), 7);
    pdu(0, 22, 1, &[(9, 1, b.finish())])
}

/// OVERLOAD STOP (§9.2.6.11): initiatingMessage, id-OverloadStop 23, reject;
/// OverloadStopIEs is empty, so an empty container.
pub(crate) fn overload_stop() -> Vec<u8> {
    pdu(0, 23, 0, &[])
}

/// PAGING (§9.2.4.1): initiatingMessage, id-Paging 24, ignore; every IE
/// criticality ignore, in the object-set order:
/// - id 115 UEPagingIdentity: CHOICE {fiveG-S-TMSI, choice-Extensions}, not
///   extensible, index `0`; FiveG-S-TMSI extension `0`, iE-Extensions `0`,
///   aMFSetID ten bits and aMFPointer six bits (fixed, not aligned), the low
///   bits of the value; fiveG-TMSI `OCTET STRING (SIZE(4))` aligned;
/// - id 50 PagingDRX: `ENUMERATED {v32, v64, v128, v256, ...}`, extension `0`
///   and two bits;
/// - id 103 TAIListForPaging `SIZE(1..16)`: count-1 in four bits; per item
///   extension `0`, iE-Extensions `0`; TAI extension `0`, iE-Extensions `0`,
///   PLMN and TAC `OCTET STRING (SIZE(3))`, aligned;
/// - id 52 PagingPriority: `ENUMERATED {priolevel1 .. priolevel8, ...}`,
///   extension `0` and three bits, priolevelN at index N-1;
/// - id 118 UERadioCapabilityForPaging and id 11 AssistanceDataForPaging:
///   the SEQUENCE values the caller gives, already encodings of their types;
/// - id 51 PagingOrigin: `ENUMERATED {non-3gpp, ...}`, extension `0` and no
///   index bits (one root value), padded -> `00`.
pub(crate) fn paging(m: &t::Paging) -> Vec<u8> {
    let t::UePagingIdentity::FiveGSTmsi {
        amf_set_id,
        amf_pointer,
        tmsi,
    } = &m.ue_paging_identity;
    let mut identity = Bits::default();
    identity
        .bit(false)
        .field(0, 2)
        .field(u64::from(*amf_set_id), 10)
        .field(u64::from(*amf_pointer), 6)
        .octets(&tmsi.to_be_bytes());
    let mut ies = vec![(115, 1, identity.finish())];
    if let Some(drx) = m.paging_drx {
        let index = match drx {
            t::PagingDrx::V32 => 0,
            t::PagingDrx::V64 => 1,
            t::PagingDrx::V128 => 2,
            t::PagingDrx::V256 => 3,
        };
        let mut b = Bits::default();
        b.bit(false).field(index, 2);
        ies.push((50, 1, b.finish()));
    }
    assert!((1..=16).contains(&m.tai_list.len()));
    let mut tais = Bits::default();
    tais.field(m.tai_list.len() as u64 - 1, 4);
    for tai in &m.tai_list {
        tais.field(0, 4).octets(&tai.tai_plmn).octets(&tai.tai_tac);
    }
    ies.push((103, 1, tais.finish()));
    if let Some(priority) = m.paging_priority {
        let index = match priority {
            t::PagingPriority::Priolevel1 => 0,
            t::PagingPriority::Priolevel2 => 1,
            t::PagingPriority::Priolevel3 => 2,
            t::PagingPriority::Priolevel4 => 3,
            t::PagingPriority::Priolevel5 => 4,
            t::PagingPriority::Priolevel6 => 5,
            t::PagingPriority::Priolevel7 => 6,
            t::PagingPriority::Priolevel8 => 7,
        };
        let mut b = Bits::default();
        b.bit(false).field(index, 3);
        ies.push((52, 1, b.finish()));
    }
    if let Some(radio) = &m.ue_radio_capability {
        ies.push((118, 1, radio.clone()));
    }
    if let Some(t::PagingOrigin::Non3gpp) = m.paging_origin {
        ies.push((51, 1, vec![0x00]));
    }
    if let Some(assistance) = &m.assistance_data {
        ies.push((11, 1, assistance.clone()));
    }
    pdu(0, 24, 1, &ies)
}

/// HANDOVER PREPARATION FAILURE (§9.2.3.3): unsuccessfulOutcome,
/// id-HandoverPreparation 12, reject; ids 10 AMF-UE-NGAP-ID, 85
/// RAN-UE-NGAP-ID and 15 Cause, all ignore. No Criticality Diagnostics.
pub(crate) fn handover_preparation_failure(amf: u64, ran: u32, cause: (u64, u64)) -> Vec<u8> {
    pdu(
        2,
        12,
        0,
        &[
            (10, 1, amf_ue_ngap_id(amf)),
            (85, 1, ran_ue_ngap_id(ran)),
            (15, 1, cause_value(cause.0, cause.1)),
        ],
    )
}

/// HANDOVER CANCEL ACKNOWLEDGE (§9.2.3.12): successfulOutcome,
/// id-HandoverCancel 10, reject; ids 10 and 85, ignore; id 19
/// CriticalityDiagnostics (ignore) when there is something to report.
pub(crate) fn handover_cancel_acknowledge(
    amf: u64,
    ran: u32,
    diagnostics: &[IeDiagnostic],
) -> Vec<u8> {
    let mut ies = vec![(10, 1, amf_ue_ngap_id(amf)), (85, 1, ran_ue_ngap_id(ran))];
    if !diagnostics.is_empty() {
        ies.push((19, 1, criticality_diagnostics(None, diagnostics)));
    }
    pdu(1, 10, 0, &ies)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each derivation against octets worked out by hand, octet by octet.
    #[test]
    fn the_derivations_write_the_hand_worked_octets() {
        // Cause radioNetwork/unspecified: `000` `0` `000000` + pad -> `00 00`.
        assert_eq!(cause_value(0, 0), [0x00, 0x00]);
        // radioNetwork release-due-to-pre-emption (46, the second addition):
        // `000` `1` `0` `000001` + pad: `0001 0000`, `001` + pad -> `10 20`.
        // (My first working read `10 08`, mis-splitting the eleven bits.)
        assert_eq!(cause_value(0, 46), [0x10, 0x20]);
        // misc/unspecified: `100` `0` `101` + pad -> `8a`.
        assert_eq!(cause_value(4, 5), [0x8a]);
        // protocol/semantic-error: `011` `0` `100` + pad -> `68`.
        assert_eq!(cause_value(3, 4), [0x68]);

        // NG Setup Response, the stage A vector: "nextgcore-amf", one GUAMI
        // 001/01 region 2 set 1 pointer 1, capacity 255, 001/01 SST 1.
        assert_eq!(
            ng_setup_response(
                "nextgcore-amf",
                &[([0x00, 0xf1, 0x10], 2, 1, 1)],
                255,
                &[([0x00, 0xf1, 0x10], vec![(1, None)])],
                &[],
            ),
            [
                0x20, 0x15, 0x00, 0x33, 0x00, 0x00, 0x04, //
                0x00, 0x01, 0x00, 0x0f, 0x06, 0x00, b'n', b'e', b'x', b't', b'g', b'c', b'o', b'r',
                b'e', b'-', b'a', b'm', b'f', //
                0x00, 0x60, 0x00, 0x08, 0x00, 0x00, 0x00, 0xf1, 0x10, 0x02, 0x00, 0x41, //
                0x00, 0x56, 0x40, 0x01, 0xff, //
                0x00, 0x50, 0x00, 0x08, 0x00, 0x00, 0xf1, 0x10, 0x00, 0x00, 0x00, 0x08,
            ]
        );

        // Criticality Diagnostics, the stage A vector: procedure 21
        // (initiating, reject): `0 111 1 0` + pad -> `78`, `15`, `00 00`
        // + pad -> `00`; count-1 `01`; IE 27 reject missing; IE 9999 notify
        // not-understood.
        let items = [
            IeDiagnostic {
                ie_id: 27,
                criticality: 0,
                type_of_error: 1,
            },
            IeDiagnostic {
                ie_id: 9999,
                criticality: 2,
                type_of_error: 0,
            },
        ];
        assert_eq!(
            criticality_diagnostics(Some((21, 0, 0)), &items),
            [0x78, 0x15, 0x00, 0x01, 0x00, 0x00, 0x1b, 0x48, 0x27, 0x0f, 0x00]
        );
        // NG Setup Failure misc/unspecified, v10s `0 011` -> `30`, and the
        // items without the procedure fields: `0 000 1 0` + pad -> `08`.
        // Value 3 + 5 + 5 + 13 = 26 octets.
        assert_eq!(
            ng_setup_failure((4, 5), Some(3), &items),
            [
                0x40, 0x15, 0x00, 0x1a, 0x00, 0x00, 0x03, //
                0x00, 0x0f, 0x40, 0x01, 0x8a, //
                0x00, 0x6b, 0x40, 0x01, 0x30, //
                0x00, 0x13, 0x40, 0x09, 0x08, 0x01, 0x00, 0x00, 0x1b, 0x48, 0x27, 0x0f, 0x00,
            ]
        );

        // NG Reset Acknowledge, one item with both IDs 0: count `01`; item
        // `0 1 1 0`, AMF count-1 `000` + pad -> `60`, `00`; RAN count-1 `00`
        // + pad -> `00`, `00`.
        let item = t::UeAssociatedLogicalNgConnectionItem {
            amf_ue_ngap_id: Some(0),
            ran_ue_ngap_id: Some(0),
        };
        assert_eq!(
            ng_reset_acknowledge(Some(&[item]), &[]),
            [
                0x20, 0x14, 0x00, 0x0c, 0x00, 0x00, 0x01, //
                0x00, 0x6f, 0x40, 0x05, 0x01, 0x60, 0x00, 0x00, 0x00,
            ]
        );
        assert_eq!(
            ng_reset_acknowledge(None, &[]),
            [0x20, 0x14, 0x00, 0x03, 0x00, 0x00, 0x00]
        );

        // Overload Start 40%: 39 in seven bits `0100111` + pad -> `4e`.
        assert_eq!(
            overload_start(40),
            [0x00, 0x16, 0x40, 0x08, 0x00, 0x00, 0x01, 0x00, 0x09, 0x40, 0x01, 0x4e]
        );
        assert_eq!(overload_stop(), [0x00, 0x17, 0x00, 0x03, 0x00, 0x00, 0x00]);

        // Paging with every optional IE: set 1, pointer 1, TMSI 0x12345678
        // (`000` `0000000001` `000001` + pad -> `00 08 20`); DRX v256 `0 11`
        // -> `60`; one TAI; priolevel8 `0 111` -> `70`; radio capability,
        // origin and assistance one octet `00` each. Value 3 + 11 + 5 + 11 +
        // 4 x 5 = 50 octets.
        let paging_all = t::Paging {
            ue_paging_identity: t::UePagingIdentity::FiveGSTmsi {
                amf_set_id: 1,
                amf_pointer: 1,
                tmsi: 0x1234_5678,
            },
            paging_drx: Some(t::PagingDrx::V256),
            tai_list: vec![t::TaiListItem {
                tai_plmn: [0x00, 0xf1, 0x10],
                tai_tac: [0x00, 0x00, 0x01],
            }],
            paging_priority: Some(t::PagingPriority::Priolevel8),
            ue_radio_capability: Some(vec![0x00]),
            paging_origin: Some(t::PagingOrigin::Non3gpp),
            assistance_data: Some(vec![0x00]),
        };
        assert_eq!(
            paging(&paging_all),
            [
                0x00, 0x18, 0x40, 0x32, 0x00, 0x00, 0x07, //
                0x00, 0x73, 0x40, 0x07, 0x00, 0x08, 0x20, 0x12, 0x34, 0x56, 0x78, //
                0x00, 0x32, 0x40, 0x01, 0x60, //
                0x00, 0x67, 0x40, 0x07, 0x00, 0x00, 0xf1, 0x10, 0x00, 0x00, 0x01, //
                0x00, 0x34, 0x40, 0x01, 0x70, //
                0x00, 0x76, 0x40, 0x01, 0x00, //
                0x00, 0x33, 0x40, 0x01, 0x00, //
                0x00, 0x0b, 0x40, 0x01, 0x00,
            ]
        );

        // Handover Preparation Failure 1/2, protocol/semantic-error `68`:
        // value 3 + 6 + 6 + 5 = 20 octets.
        assert_eq!(
            handover_preparation_failure(1, 2, (3, 4)),
            [
                0x40, 0x0c, 0x00, 0x14, 0x00, 0x00, 0x03, //
                0x00, 0x0a, 0x40, 0x02, 0x00, 0x01, //
                0x00, 0x55, 0x40, 0x02, 0x00, 0x02, //
                0x00, 0x0f, 0x40, 0x01, 0x68,
            ]
        );
        // Handover Cancel Acknowledge 1/2 with IE 9999 notify reported:
        // diagnostics `08`, count-1 `00`, item `0 0 10` + pad -> `20`, id
        // `27 0f`, typeOfError `0 0` + pad -> `00`: six octets.
        assert_eq!(
            handover_cancel_acknowledge(1, 2, &items[1..]),
            [
                0x20, 0x0a, 0x00, 0x19, 0x00, 0x00, 0x03, //
                0x00, 0x0a, 0x40, 0x02, 0x00, 0x01, //
                0x00, 0x55, 0x40, 0x02, 0x00, 0x02, //
                0x00, 0x13, 0x40, 0x06, 0x08, 0x00, 0x20, 0x27, 0x0f, 0x00,
            ]
        );
    }
}
