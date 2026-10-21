//! Conformance of the generated codec against vectors it did not produce: the
//! nextgsim gNB's captures, and octets derived by hand from TS 38.413 and X.691
//! (each derivation is written out beside its vector). The generated codec must
//! decode each one and re-encode it byte for byte.
//!
//! #417: these used to take PDUs from the hand-written `nextgcore-ngap`
//! builders. Those cross-checks moved to `nextgcore-ngap/tests/`, with their
//! subject; nothing here depends on that crate or on `nextgcore-asn1c`.

use super::*;
use bitvec::field::BitField;

fn unhex(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("valid hex"))
        .collect()
}

/// The nextgsim gNB's InitialUEMessage without and with AllowedNSSAI (IE 0).
/// The same captures pin `nextgcore-ngap`'s parser in
/// `nextgcore-ngap/tests/decode_sim_initial_ue.rs`.
const SIM_INITIAL_UE: &str = "000f404200000500550002000100260018177e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e0079000f4099f907000000010099f907000001005a4001180070400100";
const SIM_INITIAL_UE_WITH_ALLOWED_NSSAI: &str = "000f404800000600550002000100260018177e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e0079000f4099f907000000010099f907000001005a4001180070400100000000020001";

fn assert_round_trips(bytes: &[u8]) -> NGAP_PDU {
    let pdu =
        decode(bytes).unwrap_or_else(|e| panic!("generated codec rejected {bytes:02x?}: {e:?}"));
    let reencoded = encode(&pdu).expect("re-encode");
    assert_eq!(
        reencoded, bytes,
        "generated re-encoding must be byte-identical"
    );
    pdu
}

#[test]
fn sim_initial_ue_messages_decode_and_reencode_identically() {
    for capture in [SIM_INITIAL_UE, SIM_INITIAL_UE_WITH_ALLOWED_NSSAI] {
        let bytes = unhex(capture);
        let pdu = assert_round_trips(&bytes);
        assert!(
            matches!(pdu, NGAP_PDU::InitiatingMessage(_)),
            "InitialUEMessage is an InitiatingMessage, got {pdu:?}"
        );
        assert_eq!(
            bytes[0], 0x00,
            "byte 0 carries the InitiatingMessage CHOICE index"
        );
        // Byte 1 is the procedure code: id-InitialUEMessage = 15.
        assert_eq!(bytes[1], 15, "byte 1 is the procedure code");
    }
}

/// A bare PDUSessionResourceReleaseResponseTransfer -- extension bit and
/// iE-Extensions presence bit, both 0 -- is the one zero octet, and it decodes
/// back.
#[test]
fn a_contained_encoding_is_never_empty_and_round_trips() {
    let bare = generated::PDUSessionResourceReleaseResponseTransfer {
        ie_extensions: None,
    };
    let bytes = encode_contained(&bare).expect("encode");
    assert_eq!(bytes, [0x00]);
    assert_eq!(
        decode_contained::<generated::PDUSessionResourceReleaseResponseTransfer>(&bytes)
            .expect("decode"),
        bare
    );
}

/// A contained value that is not octet-aligned is padded to the octet: a
/// PDUSessionResourceReleaseCommandTransfer with Cause nas/normal-release is
/// 8 bits; radioNetwork/release-due-to-pre-emption, an extension value whose
/// index travels as a normally small number, 13 -- two octets.
#[test]
fn contained_encodings_are_octet_aligned() {
    use generated::{Cause, CauseNas, CauseRadioNetwork, PDUSessionResourceReleaseCommandTransfer};
    let normal = PDUSessionResourceReleaseCommandTransfer {
        cause: Cause::Nas(CauseNas(CauseNas::NORMAL_RELEASE)),
        ie_extensions: None,
    };
    assert_eq!(encode_contained(&normal).expect("encode"), [0x10]);
    let pre_emption = PDUSessionResourceReleaseCommandTransfer {
        cause: Cause::RadioNetwork(CauseRadioNetwork(46)),
        ie_extensions: None,
    };
    let bytes = encode_contained(&pre_emption).expect("encode");
    assert_eq!(bytes.len(), 2);
    assert_eq!(
        decode_contained::<PDUSessionResourceReleaseCommandTransfer>(&bytes).expect("decode"),
        pre_emption
    );
}

/// A contained transfer carrying a protocol IE the schema has no entry for:
/// [`decode_contained`] fails the whole transfer on it, and
/// [`decode_contained_with_unknown_ies`] returns the transfer as if the IE were
/// absent, with the IE's id, criticality and value alongside.
#[test]
fn a_contained_transfer_skips_an_unknown_ie_only_when_asked() {
    use generated::{
        PDUSessionResourceSetupRequestTransfer as Transfer,
        PDUSessionResourceSetupRequestTransferProtocolIEs as Ies,
        PDUSessionResourceSetupRequestTransferProtocolIEs_Entry as Entry,
        PDUSessionResourceSetupRequestTransferProtocolIEs_EntryValue as Ie,
    };
    let transfer = Transfer {
        protocol_i_es: Ies(vec![Entry {
            id: generated::ProtocolIE_ID(generated::ID_PDU_SESSION_TYPE),
            criticality: generated::Criticality(generated::Criticality::REJECT),
            value: Ie::Id_PDUSessionType(generated::PDUSessionType(
                generated::PDUSessionType::IPV4,
            )),
        }]),
    };
    let mut bytes = encode_contained(&transfer).expect("encode");
    // [0] extension bit and padding, [1..3] the IE count; the IEs are
    // octet-aligned, so one more appended after the last is well formed: id
    // 9999, criticality ignore (0x40), a one-octet value.
    assert_eq!(&bytes[..3], &[0x00, 0x00, 0x01]);
    bytes[2] = 0x02;
    bytes.extend_from_slice(&[0x27, 0x0f, 0x40, 0x01, 0xab]);

    assert!(decode_contained::<Transfer>(&bytes).is_err());
    let (decoded, unknown) = decode_contained_with_unknown_ies::<Transfer>(&bytes).expect("decode");
    assert_eq!(decoded, transfer);
    assert_eq!(
        unknown,
        vec![UnknownIe {
            id: 9999,
            criticality: Some(generated::Criticality::IGNORE),
            value: vec![0xab],
        }]
    );
}

/// The NG Setup Response amfd sends, as octets derived by hand from X.691
/// (ALIGNED) and the TS 38.413 V17.9 schema, not from either encoder: AMF name
/// "nextgcore-amf", one served GUAMI (PLMN 001/01, region 2, set 1, pointer
/// 1), relative capacity 255, one PLMN with SST 1.
///
/// - `20` NGAP-PDU CHOICE: ext `0`, successfulOutcome index `01`, padded;
///   `15` procedure 21 (id-NGSetup); `00` criticality reject, padded; `33`
///   value length 51.
/// - value: `00` SEQUENCE ext + pad; `00 04` four IEs (count 0..65535, two
///   aligned octets).
/// - IE 1 AMFName `00 01`, reject `00`, length `0f`: PrintableString
///   (SIZE(1..150, ...)): ext `0`, length-1 = 12 in 8 bits -> `06 00`
///   (padded), then 13 aligned 8-bit characters.
/// - IE 96 ServedGUAMIList `00 60`, reject `00`, length `08`: count-1 in
///   1..256 (range 256: one aligned octet, X.691 §11.5.7.2) `00`; item
///   ext/backupAMFName/iE-Extensions `000`, GUAMI ext/iE-Extensions `00`,
///   padded -> `00`; PLMN `00 f1 10` (fixed 3 octets, aligned); aMFRegionID 8 + aMFSetID 10 + aMFPointer 6 bits
///   `00000010 0000000001 000001` -> `02 00 41`.
/// - IE 86 RelativeAMFCapacity `00 56`, ignore `40`, length `01`: INTEGER
///   (0..255), one aligned octet `ff`.
/// - IE 80 PLMNSupportList `00 50`, reject `00`, length `08`: count-1 in 4
///   bits (1..12), item ext/iE-Extensions `00` -> `00`; PLMN `00 f1 10`;
///   SliceSupportList count-1 in 1..1024, two aligned octets (X.691
///   §11.5.7.3) `00 00`; SliceSupportItem ext/iE-Ext `00`, S-NSSAI
///   ext/sD/iE-Ext `000`, SST (fixed one octet, not aligned) `00000001` = 13
///   bits -> `00 08`.
const NG_SETUP_RESPONSE: [u8; 55] = [
    0x20, 0x15, 0x00, 0x33, // PDU header
    0x00, 0x00, 0x04, // value: extension bit, 4 IEs
    0x00, 0x01, 0x00, 0x0f, 0x06, 0x00, b'n', b'e', b'x', b't', b'g', b'c', b'o', b'r', b'e', b'-',
    b'a', b'm', b'f', // AMFName
    0x00, 0x60, 0x00, 0x08, 0x00, 0x00, 0x00, 0xf1, 0x10, 0x02, 0x00, 0x41, // ServedGUAMIList
    0x00, 0x56, 0x40, 0x01, 0xff, // RelativeAMFCapacity
    0x00, 0x50, 0x00, 0x08, 0x00, 0x00, 0xf1, 0x10, 0x00, 0x00, 0x00, 0x08, // PLMNSupportList
];

#[test]
fn ng_setup_response_matches_hand_derived_octets() {
    use generated::{NGSetupResponseProtocolIEs_EntryValue as Ie, SuccessfulOutcomeValue};
    let NGAP_PDU::SuccessfulOutcome(outcome) = assert_round_trips(&NG_SETUP_RESPONSE) else {
        panic!("NG Setup Response is a SuccessfulOutcome");
    };
    let SuccessfulOutcomeValue::Id_NGSetup(rsp) = outcome.value else {
        panic!("NG Setup Response");
    };
    let ies = &rsp.protocol_i_es.0;
    assert_eq!(ies.len(), 4);
    let Ie::Id_AMFName(name) = &ies[0].value else {
        panic!("AMFName first");
    };
    assert_eq!(name.0, "nextgcore-amf");
    let Ie::Id_ServedGUAMIList(guamis) = &ies[1].value else {
        panic!("ServedGUAMIList second");
    };
    let guami = &guamis.0[0].guami;
    assert_eq!(guami.plmn_identity.0, [0x00, 0xf1, 0x10]);
    assert_eq!(guami.amf_region_id.0.load_be::<u8>(), 2);
    assert_eq!(guami.amf_set_id.0.load_be::<u16>(), 1);
    assert_eq!(guami.amf_pointer.0.load_be::<u8>(), 1);
    let Ie::Id_RelativeAMFCapacity(capacity) = &ies[2].value else {
        panic!("RelativeAMFCapacity third");
    };
    assert_eq!(capacity.0, 255);
    assert_eq!(ies[2].criticality.0, generated::Criticality::IGNORE);
    let Ie::Id_PLMNSupportList(plmns) = &ies[3].value else {
        panic!("PLMNSupportList fourth");
    };
    assert_eq!(plmns.0[0].slice_support_list.0[0].s_nssai.sst.0, [1]);
    assert!(plmns.0[0].slice_support_list.0[0].s_nssai.sd.is_none());
}

/// An NG Setup Failure carrying Cause, TimeToWait and Criticality Diagnostics
/// (#445), as octets derived by hand from X.691 (ALIGNED):
///
/// - `40` unsuccessfulOutcome index `10`, padded; `15` procedure 21; `00`
///   reject; `1c` value length 28; `00` ext + pad; `00 03` three IEs.
/// - IE 15 Cause `00 0f`, ignore `40`, length `01`: CHOICE of six, not
///   extensible, misc = index 4 `100`; CauseMisc ext `0`, unspecified = 5 of
///   six `101` -> `8a`.
/// - IE 107 TimeToWait `00 6b`, ignore `40`, length `01`: ext `0`, v10s = 3
///   `011` -> `30`.
/// - IE 19 CriticalityDiagnostics `00 13`, ignore `40`, length `0b`: ext `0`,
///   presence `1111 0` (procedureCode, triggeringMessage, procedureCriticality,
///   IE list; no iE-Extensions) -> `78`; procedureCode 21 aligned `15`;
///   triggeringMessage initiating `00`, procedureCriticality reject `00`,
///   padded -> `00`; list count-1 in 1..256 (range 256: one aligned octet)
///   `01`; item ext/iE-Ext `00`, iECriticality reject `00`, padded -> `00`;
///   iE-ID 27 aligned `00 1b`; typeOfError ext `0` missing
///   `1`, item 2 ext/iE-Ext `00`, iECriticality notify `10` -> `48`; iE-ID 9999
///   `27 0f`; typeOfError ext `0` not-understood `0` -> `00`.
const NG_SETUP_FAILURE_WITH_DIAGNOSTICS: [u8; 32] = [
    0x40, 0x15, 0x00, 0x1c, // PDU header
    0x00, 0x00, 0x03, // value: extension bit, 3 IEs
    0x00, 0x0f, 0x40, 0x01, 0x8a, // Cause misc/unspecified
    0x00, 0x6b, 0x40, 0x01, 0x30, // TimeToWait v10s
    0x00, 0x13, 0x40, 0x0b, 0x78, 0x15, 0x00, 0x01, 0x00, 0x00, 0x1b, 0x48, 0x27, 0x0f,
    0x00, // CriticalityDiagnostics
];

#[test]
fn ng_setup_failure_with_diagnostics_matches_hand_derived_octets() {
    use generated::{NGSetupFailureProtocolIEs_EntryValue as Ie, UnsuccessfulOutcomeValue};
    let NGAP_PDU::UnsuccessfulOutcome(outcome) =
        assert_round_trips(&NG_SETUP_FAILURE_WITH_DIAGNOSTICS)
    else {
        panic!("NG Setup Failure is an UnsuccessfulOutcome");
    };
    let UnsuccessfulOutcomeValue::Id_NGSetup(failure) = outcome.value else {
        panic!("NG Setup Failure");
    };
    let ies = &failure.protocol_i_es.0;
    assert_eq!(ies.len(), 3, "Cause, TimeToWait, CriticalityDiagnostics");
    let Ie::Id_Cause(generated::Cause::Misc(misc)) = &ies[0].value else {
        panic!("Cause misc first");
    };
    assert_eq!(misc.0, generated::CauseMisc::UNSPECIFIED);
    let Ie::Id_TimeToWait(ttw) = &ies[1].value else {
        panic!("TimeToWait second");
    };
    assert_eq!(ttw.0, generated::TimeToWait::V10S);
    let last = ies.last().expect("IEs");
    assert_eq!(last.id.0, generated::ID_CRITICALITY_DIAGNOSTICS);
    assert_eq!(last.criticality.0, generated::Criticality::IGNORE);
    let Ie::Id_CriticalityDiagnostics(cd) = &last.value else {
        panic!("Criticality Diagnostics is the last IE");
    };
    assert_eq!(cd.procedure_code.as_ref().map(|p| p.0), Some(21));
    assert_eq!(cd.triggering_message.as_ref().map(|t| t.0), Some(0));
    assert_eq!(cd.procedure_criticality.as_ref().map(|c| c.0), Some(0));
    let list = &cd.i_es_criticality_diagnostics.as_ref().expect("IE list").0;
    assert_eq!(list.len(), 2);
    assert_eq!(list[0].ie_id.0, 27);
    assert_eq!(list[0].ie_criticality.0, generated::Criticality::REJECT);
    assert_eq!(list[0].type_of_error.0, generated::TypeOfError::MISSING);
    assert_eq!(list[1].ie_id.0, 9999);
    assert_eq!(list[1].ie_criticality.0, generated::Criticality::NOTIFY);
    assert_eq!(
        list[1].type_of_error.0,
        generated::TypeOfError::NOT_UNDERSTOOD
    );
}

/// The Paging amfd sends (UEPagingIdentity + TAIListForPaging), against octets
/// derived from X.691 by hand rather than from either encoder:
///
/// - `00` InitiatingMessage (extensible CHOICE: ext 0, index 00), padded;
///   `18` procedure 24; `40` criticality ignore; `19` value length 25.
/// - value: `00` SEQUENCE extension bit + pad; `00 02` two IEs.
/// - IE 115 `00 73`, ignore `40`, length `07`, UEPagingIdentity:
///   CHOICE index `0` (two alternatives, not extensible), FiveG-S-TMSI ext `0`,
///   iE-Extensions absent `0`, aMFSetID `0000000001`, aMFPointer `000001`
///   = 19 bits -> `00 08 20`; fiveG-TMSI OCTET STRING (SIZE(4)) octet-aligned
///   (X.691 §17.6) -> `12 34 56 78`.
/// - IE 103 `00 67`, ignore `40`, length `07`: list count 1 in 1..16 -> `0000`,
///   item ext/iE-Extensions `0 0`, TAI ext/iE-Extensions `0 0` = 8 bits `00`;
///   PLMN `00 f1 10`; TAC `00 00 01`.
///
/// The same octets pin the hand-written builder in
/// `nextgcore-ngap/tests/builder_conformance.rs`.
#[test]
fn paging_as_amfd_sends_it_round_trips() {
    let paging: [u8; 29] = [
        0x00, 0x18, 0x40, 0x19, // PDU header
        0x00, 0x00, 0x02, // value: extension bit, 2 IEs
        0x00, 0x73, 0x40, 0x07, 0x00, 0x08, 0x20, 0x12, 0x34, 0x56, 0x78, // UEPagingIdentity
        0x00, 0x67, 0x40, 0x07, 0x00, 0x00, 0xf1, 0x10, 0x00, 0x00, 0x01, // TAIListForPaging
    ];
    let pdu = assert_round_trips(&paging);
    assert!(matches!(pdu, NGAP_PDU::InitiatingMessage(_)));
}

/// SecurityContext { nextHopChainingCount 1, nextHopNH }, against hand-derived
/// octets: extension `0`, iE-Extensions absent `0`, count `001` in 0..7, then
/// the 256-bit SecurityKey octet-aligned (X.691 §16.10) -> `08` followed by
/// the 32 key octets unshifted.
#[test]
fn security_context_key_is_octet_aligned() {
    let ctx = generated::SecurityContext {
        next_hop_chaining_count: generated::NextHopChainingCount(1),
        next_hop_nh: generated::SecurityKey(bitvec::vec::BitVec::from_slice(&[0x22; 32])),
        ie_extensions: None,
    };
    let mut expected = vec![0x08];
    expected.extend_from_slice(&[0x22; 32]);
    assert_eq!(encode_contained(&ctx).expect("encode"), expected);
    assert_eq!(
        decode_contained::<generated::SecurityContext>(&expected).expect("decode"),
        ctx
    );
}

/// MaximumDataBurstVolume ::= INTEGER (0..4095, ..., 4096..2000000), against
/// hand-derived octets. In the root: ext `0`, padded, then the value in two
/// aligned octets (range 4096, X.691 §11.5.7.3). Past the root: ext `1`,
/// padded, then an unconstrained whole number (X.691 §12.1, the extension
/// constraint not visible): a length octet and the minimal two's-complement
/// octets, so 65535 takes three.
///
/// #417: the hand-written cross-check that covered this boundary moved to
/// `nextgcore-ngap/tests/hand_written_transfer_cross_check.rs`; this pins the
/// generated codec alone.
#[test]
fn maximum_data_burst_volume_matches_hand_derived_octets() {
    for (v, octets) in [
        (0u32, &[0x00, 0x00, 0x00][..]),
        (4095, &[0x00, 0x0f, 0xff]),
        (4096, &[0x80, 0x02, 0x10, 0x00]),
        (65535, &[0x80, 0x03, 0x00, 0xff, 0xff]),
        (65536, &[0x80, 0x03, 0x01, 0x00, 0x00]),
        (2_000_000, &[0x80, 0x03, 0x1e, 0x84, 0x80]),
    ] {
        let mdbv = generated::MaximumDataBurstVolume(v);
        assert_eq!(encode_contained(&mdbv).expect("encode"), octets, "{v}");
        assert_eq!(
            decode_contained::<generated::MaximumDataBurstVolume>(octets).expect("decode"),
            mdbv,
            "{v}"
        );
    }
}

/// PacketLossRate ::= INTEGER (0..1000, ...), against hand-derived octets: ext
/// `0`, padded, then two aligned octets (range 1001), either side of an octet
/// boundary and at the root's bounds.
#[test]
fn packet_loss_rate_matches_hand_derived_octets() {
    for (v, octets) in [
        (0u16, [0x00, 0x00, 0x00]),
        (255, [0x00, 0x00, 0xff]),
        (256, [0x00, 0x01, 0x00]),
        (1000, [0x00, 0x03, 0xe8]),
    ] {
        let rate = generated::PacketLossRate(v);
        assert_eq!(encode_contained(&rate).expect("encode"), octets, "{v}");
        assert_eq!(
            decode_contained::<generated::PacketLossRate>(&octets).expect("decode"),
            rate,
            "{v}"
        );
    }
}
