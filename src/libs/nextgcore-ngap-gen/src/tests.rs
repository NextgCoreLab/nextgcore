//! Cross-codec conformance: the generated codec must accept, and re-encode byte
//! for byte, the PDUs the hand-written codec and the nextgsim gNB already put on
//! the wire. If it does not, one of the two codecs misreads TS 38.413, and the
//! later migration stages would change wire behaviour without anyone noticing.

use super::*;
use nextgcore_ngap::builder::build_ng_setup_response;
use nextgcore_ngap::types::{Guami, NgSetupResponse, PlmnSupportItem, SNssai, ServedGuamiItem};

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
fn hand_written_ng_setup_response_decodes_and_reencodes_identically() {
    let bytes = build_ng_setup_response(&NgSetupResponse {
        amf_name: "nextgcore-amf".to_string(),
        served_guami_list: vec![ServedGuamiItem {
            guami: Guami {
                plmn_identity: [0x00, 0xF1, 0x10],
                amf_region_id: 0x02,
                amf_set_id: 0x001,
                amf_pointer: 0x01,
            },
            backup_amf_name: None,
        }],
        relative_amf_capacity: 255,
        plmn_support_list: vec![PlmnSupportItem {
            plmn_identity: [0x00, 0xF1, 0x10],
            slice_support_list: vec![SNssai { sst: 1, sd: None }],
        }],
    })
    .expect("hand-written builder");

    let pdu = assert_round_trips(&bytes);
    assert!(
        matches!(pdu, NGAP_PDU::SuccessfulOutcome(_)),
        "NG Setup Response is a SuccessfulOutcome, got {pdu:?}"
    );
    // Outer CHOICE: extension bit 0, then index 1 in two bits -> 0b0010_0000.
    assert_eq!(
        bytes[0], 0x20,
        "byte 0 carries the SuccessfulOutcome CHOICE index"
    );
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
/// back. The hand-written `nextgcore-ngap` transfer codec agrees.
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
    assert_eq!(
        nextgcore_ngap::transfer::PduSessionResourceReleaseResponseTransfer
            .encode()
            .expect("hand-written encode"),
        bytes
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
