//! #417 stage B3.2: the UE Context Release and PDU Session Resource Setup /
//! Release messages amfd sends, their N2 SM transfers, and the few gNB->AMF
//! shapes the `ngap_asn1.rs` tests of those procedures need beyond
//! [`crate::gnb_pdus`]. Derived by hand from the TS 38.413 V17.9.0 ASN.1 and
//! X.691 ALIGNED (see [`crate::amf_pdus`]); never from the hand-written codec.
//!
//! Layout facts used below beyond those in [`crate::aper_golden`]:
//! - an unconstrained length determinant of 16384 octets or more is
//!   fragmented (X.691 §11.9.3.8): `11` + six bits m (1..4), then m x 16K
//!   octets, repeated while 16K or more remain, the largest m first; then the
//!   remainder with an ordinary length determinant, `00` when nothing is left;
//! - `INTEGER (0..255)` (ProcedureCode, PDUSessionID) is one aligned octet
//!   (§11.5.7.2, range 256);
//! - `OCTET STRING (SIZE(1))` (SST) is fixed and at most two octets, so it is
//!   NOT aligned; `OCTET STRING (SIZE(3))` (SD, PLMNIdentity) is aligned with
//!   no length (§17.6, §17.7);
//! - an extensible ENUMERATED is its extension bit, then a root value as its
//!   index in the fewest bits that hold the root count, or an addition as the
//!   normally small number `0` + six bits of its addition index (§11.6.1,
//!   §10.6.1).

use crate::aper_golden::Bits;

/// AMF-UE-NGAP-ID `INTEGER (0..1099511627775)` (§9.3.3.1).
pub(crate) const MAX_AMF_UE_NGAP_ID: u64 = (1 << 40) - 1;

/// `INTEGER (0..ub)` with ub past 64K, into a running sink: the octet count
/// n-1 in `width` bits, unaligned, then n aligned octets, n minimal
/// (§11.5.7.4). AMF-UE-NGAP-ID has `width` 3, RAN-UE-NGAP-ID 2.
fn long_integer(b: &mut Bits, value: u64, width: u32) {
    let be = value.to_be_bytes();
    let skip = be.iter().take_while(|o| **o == 0).count().min(7);
    b.field((8 - skip) as u64 - 1, width).octets(&be[skip..]);
}

/// The AMF-UE-NGAP-ID IE value; `None` past its upper bound, which no
/// encoding of the type can carry.
pub(crate) fn amf_ue_ngap_id(v: u64) -> Option<Vec<u8>> {
    (v <= MAX_AMF_UE_NGAP_ID).then(|| {
        let mut b = Bits::default();
        long_integer(&mut b, v, 3);
        b.finish()
    })
}

/// The RAN-UE-NGAP-ID IE value, `INTEGER (0..4294967295)`.
pub(crate) fn ran_ue_ngap_id(v: u32) -> Vec<u8> {
    let mut b = Bits::default();
    long_integer(&mut b, u64::from(v), 2);
    b.finish()
}

/// Per Cause group (§9.3.1.2, ASN.1 `Cause`): its CHOICE index, how many
/// values its ENUMERATED root has, the bits a root index takes, and how many
/// extension additions V17.9 lists.
/// - radioNetwork: 45 root values (unspecified ..
///   release-due-to-cn-detected-mobility), six bits; 12 additions
///   (n26-interface-not-available .. misaligned-association-for-multicast-unicast);
/// - transport: 2, one bit; no additions;
/// - nas: 4, two bits; one addition (uE-not-in-PLMN-serving-area);
/// - protocol: 7, three bits; no additions;
/// - misc: 6, three bits; no additions.
const CAUSE_GROUPS: [(u64, u64, u32, u64); 5] = [
    (0, 45, 6, 12),
    (1, 2, 1, 0),
    (2, 4, 2, 1),
    (3, 7, 3, 0),
    (4, 6, 3, 0),
];

/// Every wire value a Cause group can carry: its root then its additions,
/// numbered on from the root as the generated value numbers them.
pub(crate) fn cause_values(group: u8) -> std::ops::Range<u8> {
    let (_, root, _, additions) = CAUSE_GROUPS[usize::from(group)];
    0..(root + additions) as u8
}

/// A Cause, group `group` (0 radioNetwork .. 4 misc) and wire value `value`:
/// the CHOICE of six (`choice-Extensions` is the sixth alternative, and there
/// is no `...`) in three bits; then the group's ENUMERATED: extension `0` and
/// the root index, or extension `1`, `0` and the addition index in six bits.
pub(crate) fn cause(b: &mut Bits, group: u8, value: u8) {
    let (choice, root, width, additions) = CAUSE_GROUPS[usize::from(group)];
    let v = u64::from(value);
    assert!(
        v < root + additions,
        "cause {group}/{value} is not in V17.9"
    );
    b.field(choice, 3);
    if v < root {
        b.bit(false).field(v, width);
    } else {
        b.bit(true).bit(false).field(v - root, 6);
    }
}

/// The Cause IE value on its own.
pub(crate) fn cause_value(group: u8, value: u8) -> Vec<u8> {
    let mut b = Bits::default();
    cause(&mut b, group, value);
    b.finish()
}

/// UE-NGAP-IDs (§9.3.3.21): a CHOICE of three, not extensible, two bits.
/// uE-NGAP-ID-pair `00`: the pair SEQUENCE's extension bit `0` and
/// iE-Extensions presence `0`, then the AMF UE NGAP ID and the RAN UE NGAP ID
/// as long integers. aMF-UE-NGAP-ID `01`: the AMF UE NGAP ID alone.
fn ue_ngap_ids(amf: u64, ran: Option<u32>) -> Option<Vec<u8>> {
    if amf > MAX_AMF_UE_NGAP_ID {
        return None;
    }
    let mut b = Bits::default();
    match ran {
        Some(ran) => {
            b.field(0, 2).bit(false).bit(false);
            long_integer(&mut b, amf, 3);
            long_integer(&mut b, u64::from(ran), 2);
        }
        None => {
            b.field(1, 2);
            long_integer(&mut b, amf, 3);
        }
    }
    Some(b.finish())
}

/// UE CONTEXT RELEASE COMMAND (§9.2.2.5): initiatingMessage,
/// id-UEContextRelease 41, reject; id 114 UE-NGAP-IDs (reject); id 15 Cause
/// (ignore). `None` for an AMF UE NGAP ID past 2^40-1.
pub(crate) fn ue_context_release_command(
    amf: u64,
    ran: Option<u32>,
    group: u8,
    value: u8,
) -> Option<Vec<u8>> {
    Some(crate::aper_golden::pdu(
        0,
        41,
        0,
        &[
            (114, 0, ue_ngap_ids(amf, ran)?),
            (15, 1, cause_value(group, value)),
        ],
    ))
}

/// PDUSessionResourceReleaseCommandTransfer (§9.3.4.12): extension `0`,
/// iE-Extensions presence `0`, the Cause, padded.
pub(crate) fn release_command_transfer(group: u8, value: u8) -> Vec<u8> {
    let mut b = Bits::default();
    b.bit(false).bit(false);
    cause(&mut b, group, value);
    b.finish()
}

/// PDU SESSION RESOURCE RELEASE COMMAND (§9.2.1.3) as amfd builds it:
/// initiatingMessage, id-PDUSessionResourceRelease 28, reject; ids 10 and 85
/// (reject); id 79 PDUSessionResourceToReleaseListRelCmd (reject),
/// `SIZE(1..256)`: count-1 in one aligned octet (range 256); per item
/// extension `0`, iE-Extensions `0`, the PDU Session ID octet, then the
/// transfer (Cause nas/normal-release, [`release_command_transfer`]) as an
/// OCTET STRING with its length. `None` for an empty or 257-item list or an
/// AMF UE NGAP ID past 2^40-1.
pub(crate) fn pdu_session_resource_release_command(
    amf: u64,
    ran: u32,
    psis: &[u8],
) -> Option<Vec<u8>> {
    if !(1..=256).contains(&psis.len()) {
        return None;
    }
    let transfer = release_command_transfer(2, 0);
    let mut list = Bits::default();
    list.octets(&[(psis.len() - 1) as u8]);
    for psi in psis {
        list.field(0, 2).octets(&[*psi]);
        list.open(&transfer);
    }
    Some(crate::aper_golden::pdu(
        0,
        28,
        0,
        &[
            (10, 0, amf_ue_ngap_id(amf)?),
            (85, 0, ran_ue_ngap_id(ran)),
            (79, 0, list.finish()),
        ],
    ))
}

/// PDU SESSION RESOURCE SETUP REQUEST (§9.2.1.1) for one session, as amfd
/// builds it: initiatingMessage, id-PDUSessionResourceSetup 29, reject; ids 10
/// and 85 (reject); id 38 NAS-PDU (reject) when given, ahead of the list in
/// object-set order (§9.4.1); id 74 PDUSessionResourceSetupListSUReq (reject):
/// count-1 = 0 in one aligned octet; the item's extension `0`, presence
/// pDUSessionNAS-PDU `0` and iE-Extensions `0`, padded; the PDU Session ID
/// octet; S-NSSAI (§9.3.1.24) extension `0`, presence sD, iE-Extensions `0`,
/// then SST unaligned in eight bits, SD (the low 24 bits of `sd`, the AMF
/// keeping only those) in three aligned octets; then the transfer, an OCTET
/// STRING with its length. `None` for an AMF UE NGAP ID past 2^40-1.
pub(crate) fn pdu_session_resource_setup_request(
    amf: u64,
    ran: u32,
    psi: u8,
    sst: u8,
    sd: Option<u32>,
    nas: Option<&[u8]>,
    transfer: &[u8],
) -> Option<Vec<u8>> {
    let mut list = Bits::default();
    list.octets(&[0]).field(0, 3).octets(&[psi]);
    list.bit(false)
        .bit(sd.is_some())
        .bit(false)
        .field(u64::from(sst), 8);
    if let Some(sd) = sd {
        list.octets(&(sd & 0xFF_FFFF).to_be_bytes()[1..]);
    }
    list.open(transfer);
    let mut ies = vec![(10, 0, amf_ue_ngap_id(amf)?), (85, 0, ran_ue_ngap_id(ran))];
    if let Some(nas) = nas {
        ies.push((38, 0, crate::aper_golden::open_value(nas)));
    }
    ies.push((74, 0, list.finish()));
    Some(crate::aper_golden::pdu(0, 29, 0, &ies))
}

/// UE CONTEXT RELEASE REQUEST (§9.2.2.4) from a gNB, with the Cause given by
/// its wire numbers (so every V17.9 value is reachable, unlike
/// [`crate::gnb_pdus::ue_context_release_request`]'s table): initiatingMessage,
/// id-UEContextReleaseRequest 42, ignore; ids 10 and 85 (reject); id 15 Cause
/// (ignore).
pub(crate) fn ue_context_release_request(amf: u64, ran: u32, group: u8, value: u8) -> Vec<u8> {
    crate::aper_golden::pdu(
        0,
        42,
        1,
        &[
            (10, 0, amf_ue_ngap_id(amf).expect("in range")),
            (85, 0, ran_ue_ngap_id(ran)),
            (15, 1, cause_value(group, value)),
        ],
    )
}

/// A PDU session item list as the response messages carry it,
/// `SEQUENCE (SIZE(1..256)) OF`: count-1 in one aligned octet (range 256);
/// per item extension `0`, iE-Extensions `0`, the PDU Session ID octet, then
/// the transfer `OCTET STRING (CONTAINING ...)` with its length -- fragmented
/// past 16K octets, unlike [`crate::gnb_pdus`]'s.
fn session_list(items: &[(u8, Vec<u8>)]) -> Vec<u8> {
    assert!((1..=256).contains(&items.len()));
    let mut b = Bits::default();
    b.octets(&[(items.len() - 1) as u8]);
    for (psi, transfer) in items {
        b.field(0, 2).octets(&[*psi]);
        b.open(transfer);
    }
    b.finish()
}

/// PDU SESSION RESOURCE SETUP RESPONSE (§9.2.1.2) from a gNB, any transfer
/// length: successfulOutcome, id-PDUSessionResourceSetup 29, reject; ids 10
/// and 85 (ignore); id 75 PDUSessionResourceSetupListSURes and id 58
/// PDUSessionResourceFailedToSetupListSURes (ignore), each left out when
/// empty ([`session_list`]).
pub(crate) fn pdu_session_resource_setup_response(
    amf: u64,
    ran: u32,
    setup: &[(u8, Vec<u8>)],
    failed: &[(u8, Vec<u8>)],
) -> Vec<u8> {
    let mut ies = vec![
        (10, 1, amf_ue_ngap_id(amf).expect("in range")),
        (85, 1, ran_ue_ngap_id(ran)),
    ];
    for (id, items) in [(75, setup), (58, failed)] {
        if !items.is_empty() {
            ies.push((id, 1, session_list(items)));
        }
    }
    crate::aper_golden::pdu(1, 29, 0, &ies)
}

/// PDUSessionResourceSetupResponseTransfer (§9.3.4.2) as a gNB sends it with
/// one IPv4 tunnel and no optional member: extension `0`, presence
/// additionalDLQosFlowPerTNLInformation, securityResult,
/// qosFlowFailedToSetupList and iE-Extensions `0000`; QosFlowPerTNLInformation
/// (§9.3.2.8) extension `0`, iE-Extensions `0`; UPTransportLayerInformation
/// CHOICE of two (not extensible) gTPTunnel `0`; GTPTunnel extension `0`,
/// iE-Extensions `0`; TransportLayerAddress `BIT STRING (SIZE(1..160, ...))`:
/// size extension `0`, length-1 = 31 in eight bits (range 160), the 32 bits
/// aligned (ub past 16 bits); GTP-TEID `OCTET STRING (SIZE(4))` aligned;
/// AssociatedQosFlowList `SIZE(1..64)` count-1 in six bits; per item
/// extension `0`, qosFlowMappingIndication `0`, iE-Extensions `0`,
/// QosFlowIdentifier `INTEGER (0..63, ...)` extension `0` + six bits.
pub(crate) fn setup_response_transfer(teid: u32, address: [u8; 4], qfis: &[u8]) -> Vec<u8> {
    assert!((1..=64).contains(&qfis.len()));
    let mut b = Bits::default();
    b.bit(false).field(0, 4);
    b.bit(false).bit(false);
    b.bit(false);
    b.bit(false).bit(false);
    b.bit(false)
        .field(31, 8)
        .octets(&address)
        .octets(&teid.to_be_bytes());
    b.field(qfis.len() as u64 - 1, 6);
    for q in qfis {
        b.field(0, 3).bit(false).field(u64::from(*q), 6);
    }
    b.finish()
}

/// The IE fields of an NGAP-PDU, read at the framing level alone -- the
/// envelope [`crate::aper_golden::pdu`] writes -- as `(choice, procedure, criticality, IEs)`.
/// Schema-blind: it never interprets an IE value, so the tests can put a wire
/// form back in that no encoder produces.
#[allow(clippy::type_complexity)]
pub(crate) fn fields(pdu: &[u8]) -> (u64, u8, u8, Vec<(u16, u8, Vec<u8>)>) {
    /// One length determinant at `at` (fragments included) and the octets
    /// after it; returns the content and the position past it.
    fn read_open(data: &[u8], mut at: usize) -> (Vec<u8>, usize) {
        let mut out = Vec::new();
        loop {
            let l = data[at];
            if l & 0x80 == 0 {
                let n = usize::from(l);
                out.extend_from_slice(&data[at + 1..at + 1 + n]);
                return (out, at + 1 + n);
            }
            if l & 0xC0 == 0x80 {
                let n = usize::from(u16::from_be_bytes([data[at], data[at + 1]]) & 0x3FFF);
                out.extend_from_slice(&data[at + 2..at + 2 + n]);
                return (out, at + 2 + n);
            }
            let n = usize::from(l & 0x3F) * 16384;
            out.extend_from_slice(&data[at + 1..at + 1 + n]);
            at += 1 + n;
        }
    }
    let choice = u64::from(pdu[0] >> 5 & 3);
    let procedure = pdu[1];
    let criticality = pdu[2] >> 6;
    let (value, _) = read_open(pdu, 3);
    let count = u16::from_be_bytes([value[1], value[2]]);
    let mut at = 3;
    let mut ies = Vec::new();
    for _ in 0..count {
        let id = u16::from_be_bytes([value[at], value[at + 1]]);
        let c = value[at + 2] >> 6;
        let (v, next) = read_open(&value, at + 3);
        ies.push((id, c, v));
        at = next;
    }
    (choice, procedure, criticality, ies)
}

/// `pdu` with the value of its protocol IE `id` replaced by `value`, every
/// other octet of the framing re-derived through [`crate::aper_golden::pdu`].
pub(crate) fn with_ie_value(pdu: &[u8], id: u16, value: Vec<u8>) -> Vec<u8> {
    let (choice, procedure, criticality, mut ies) = fields(pdu);
    let ie = ies
        .iter_mut()
        .find(|(i, _, _)| *i == id)
        .expect("IE present");
    ie.2 = value;
    crate::aper_golden::pdu(choice, procedure, criticality, &ies)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each derivation against a vector worked out octet by octet without it.
    #[test]
    fn the_derivations_write_the_hand_worked_octets() {
        // Fragmentation: 16384 octets are `c1` + 16K, then `00`; 16385 are
        // `c1` + 16K, then `01` + one; 70000 = 4 x 16K + 4464 are `c4` + 64K,
        // then `91 70` + 4464.
        let k = vec![0xEE; 16384];
        let o = crate::aper_golden::open_value(&k);
        assert_eq!((o[0], o.len(), o[16385]), (0xC1, 16386, 0x00));
        let mut k1 = k.clone();
        k1.push(0x11);
        let o = crate::aper_golden::open_value(&k1);
        assert_eq!((o[16385], o[16386], o.len()), (0x01, 0x11, 16387));
        let o = crate::aper_golden::open_value(&vec![0; 70_000]);
        assert_eq!((o[0], o[65537], o[65538]), (0xC4, 0x91, 0x70));

        // Cause: radioNetwork/user-inactivity 20: `000 0 010100` -> `05 00`;
        // radioNetwork/release-due-to-pre-emption 46, the second addition:
        // `000 1 0 000001` -> `10 20`; nas/uE-not-in-PLMN-serving-area 4, the
        // first: `010 1 0 000000` -> `50 00`; misc/unspecified 5:
        // `100 0 101` -> `8a`.
        assert_eq!(cause_value(0, 20), [0x05, 0x00]);
        assert_eq!(cause_value(0, 46), [0x10, 0x20]);
        assert_eq!(cause_value(2, 4), [0x50, 0x00]);
        assert_eq!(cause_value(4, 5), [0x8a]);

        // UE CONTEXT RELEASE COMMAND, AMF 42 RAN 1001, nas/normal-release:
        // `00` `29` `00` length 17; `00` `00 02`; IE 114 reject, length 5:
        // pair `00`, `0 0`, AMF n-1 `000`, pad -> `00`, `2a`; RAN n-1 `01`,
        // pad -> `40`, `03 e9`; IE 15 ignore, length 1: `010 0 00` -> `40`.
        assert_eq!(
            ue_context_release_command(42, Some(1001), 2, 0).expect("in range"),
            [
                0x00, 0x29, 0x00, 0x11, 0x00, 0x00, 0x02, 0x00, 0x72, 0x00, 0x05, 0x00, 0x2a, 0x40,
                0x03, 0xe9, 0x00, 0x0f, 0x40, 0x01, 0x40,
            ]
        );
        // The AMF-only arm, AMF 1: `01` + `000`, pad -> `40`, `01`.
        let c = ue_context_release_command(1, None, 2, 0).expect("in range");
        assert_eq!(c[7..12], [0x00, 0x72, 0x00, 0x02, 0x40]);
        assert_eq!(
            ue_context_release_command(MAX_AMF_UE_NGAP_ID + 1, Some(1), 2, 0),
            None
        );

        // The Release Command Transfer, nas/normal-release: `0 0 010 0 00` ->
        // `10`.
        assert_eq!(release_command_transfer(2, 0), [0x10]);

        // PDU SESSION RESOURCE RELEASE COMMAND, AMF 42 RAN 1001, PSI 5:
        // `00 1c 00` length 25, `00 00 03`; IE 10 reject, length 2, `00 2a`;
        // IE 85 reject, length 3, `40 03 e9`; IE 79 reject, length 5: count-1
        // `00`, item `00` pad, `05`, transfer length `01`, `10`.
        assert_eq!(
            pdu_session_resource_release_command(42, 1001, &[5]).expect("in range"),
            [
                0x00, 0x1c, 0x00, 0x19, 0x00, 0x00, 0x03, 0x00, 0x0a, 0x00, 0x02, 0x00, 0x2a, 0x00,
                0x55, 0x00, 0x03, 0x40, 0x03, 0xe9, 0x00, 0x4f, 0x00, 0x05, 0x00, 0x00, 0x05, 0x01,
                0x10,
            ]
        );

        // PDU SESSION RESOURCE SETUP REQUEST, AMF 42 RAN 1001, PSI 5, SST 1,
        // SD 000102, transfer `ab cd`: `00 1d 00` length 31, `00 00 03`; IEs
        // 10 and 85 as above; IE 74 reject, length 11: count-1 `00`, item
        // `000` pad -> `00`, `05`; S-NSSAI `0 1 0` + SST `00000001`, pad ->
        // `40 20`; SD `00 01 02`; transfer `02 ab cd`.
        assert_eq!(
            pdu_session_resource_setup_request(42, 1001, 5, 1, Some(0x0102), None, &[0xab, 0xcd])
                .expect("in range"),
            [
                0x00, 0x1d, 0x00, 0x1f, 0x00, 0x00, 0x03, 0x00, 0x0a, 0x00, 0x02, 0x00, 0x2a, 0x00,
                0x55, 0x00, 0x03, 0x40, 0x03, 0xe9, 0x00, 0x4a, 0x00, 0x0b, 0x00, 0x00, 0x05, 0x40,
                0x20, 0x00, 0x01, 0x02, 0x02, 0xab, 0xcd,
            ]
        );

        // UE CONTEXT RELEASE REQUEST, AMF 7 RAN 9, radioNetwork 21
        // (radio-connection-with-ue-lost): `00 2a 40` length 21, `00 00 03`;
        // IE 10 reject `00 07`; IE 85 reject `00 09`; IE 15 ignore, length 2,
        // `000 0 010101` -> `05 40`.
        assert_eq!(
            ue_context_release_request(7, 9, 0, 21),
            [
                0x00, 0x2a, 0x40, 0x15, 0x00, 0x00, 0x03, 0x00, 0x0a, 0x00, 0x02, 0x00, 0x07, 0x00,
                0x55, 0x00, 0x02, 0x00, 0x09, 0x00, 0x0f, 0x40, 0x02, 0x05, 0x40,
            ]
        );

        // PDU SESSION RESOURCE SETUP RESPONSE, AMF 7 RAN 9, set up PSI 5 with
        // transfer `00`, failed PSI 6 with `01`: `20 1d 00` length 33, `00 00
        // 04`; IE 10 ignore `40`, length 2, `00 07`; IE 85 ignore, `00 09`; IE
        // 75 ignore, length 5: count-1 `00`, item preamble `00` + pad, PSI
        // `05`, transfer `01 00`; IE 58 ignore, length 5: `00 00 06 01 01`.
        // (My first draft said length 4 for each list and 31 for the PDU,
        // dropping the item's preamble octet; X.691 §19 puts it there.)
        assert_eq!(
            pdu_session_resource_setup_response(7, 9, &[(5, vec![0])], &[(6, vec![1])]),
            [
                0x20, 0x1d, 0x00, 0x21, 0x00, 0x00, 0x04, 0x00, 0x0a, 0x40, 0x02, 0x00, 0x07, 0x00,
                0x55, 0x40, 0x02, 0x00, 0x09, 0x00, 0x4b, 0x40, 0x05, 0x00, 0x00, 0x05, 0x01, 0x00,
                0x00, 0x3a, 0x40, 0x05, 0x00, 0x00, 0x06, 0x01, 0x01,
            ]
        );

        // The Setup Response Transfer, TEID deadbeef, 10.45.0.3, QFI 9: eleven
        // zero bits (transfer extension and four presence bits, per-TNL
        // extension and iE-Extensions, the CHOICE bit, tunnel extension and
        // iE-Extensions, the size extension), then length-1 31 `00011111`:
        // `00000000 00000011 111` + pad -> `00 03 e0`; address `0a 2d 00 03`;
        // TEID `de ad be ef`; count-1 `000000`, item `000`, QFI extension `0`,
        // `001001` -> `00 09`.
        assert_eq!(
            setup_response_transfer(0xdead_beef, [10, 45, 0, 3], &[9]),
            [0x00, 0x03, 0xe0, 0x0a, 0x2d, 0x00, 0x03, 0xde, 0xad, 0xbe, 0xef, 0x00, 0x09]
        );
    }

    /// The framing reader reads back what [`crate::aper_golden::pdu`] writes, fragments
    /// included, and [`with_ie_value`] changes only the IE it names.
    #[test]
    fn the_framing_reader_inverts_the_envelope() {
        let ies = vec![
            (10, 0, vec![0x00, 0x07]),
            (74, 0, vec![0x5a; 20_000]),
            (85, 1, vec![0x00, 0x09]),
        ];
        let pdu = crate::aper_golden::pdu(1, 29, 0, &ies);
        assert_eq!(fields(&pdu), (1, 29, 0, ies.clone()));
        let spliced = with_ie_value(&pdu, 85, vec![0x40, 0x01, 0x02]);
        let (_, _, _, back) = fields(&spliced);
        assert_eq!(back[..2], ies[..2]);
        assert_eq!(back[2], (85, 1, vec![0x40, 0x01, 0x02]));
    }
}
