//! Stage 1 cross-codec checks (#514).
//!
//! The octets below are nextgcore-s1ap's `tests/golden_x691.rs` forms, each
//! derived by hand from X.691 in #456 (not captured from an encoder). The
//! generated codec must decode every one and re-encode it byte for byte, and
//! must agree with the hand-written builders over a sweep of their inputs.

use super::{decode, decode_with_unknown_ies, encode, S1AP_PDU};
use nextgcore_asn1c::s1ap::cause::{Cause, CauseMisc, CauseNas, CauseRadioNetwork};
use nextgcore_s1ap::*;

const S1_SETUP_REQUEST: &str = "00110031000004003b00080099f907000019b0003c400e05806e6578746773696d2d656e62004000070000004099f9070089400140";
const S1_SETUP_RESPONSE: &str =
    "20110020000003003d400501006d6d650069000b000099f90700000002000100574001ff";
const S1_SETUP_FAILURE: &str = "4011000d00000200024001450041400130";
const INITIAL_UE_MESSAGE: &str = "000c402b000005000800020001001a0003020741004300060099f9070001006440080099f9070019b0100086400130";
const DOWNLINK_NAS_TRANSPORT: &str = "000b4016000003000000020001000800020001001a0003020752";
const UPLINK_NAS_TRANSPORT: &str = "000d402c000005000000020001000800020001001a0003020753006440080099f9070019b010004340060099f9070001";
const INITIAL_CONTEXT_SETUP_REQUEST: &str = "0009005d000006000000020001000800020001004200060803e82003e800180013000034000e050009040f800a00000100000001006b000518000c0000004900200000000000000000000000000000000000000000000000000000000000000000";

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// (outcome index, procedure code) of a decoded PDU.
fn shape(pdu: &S1AP_PDU) -> (u8, u8) {
    match pdu {
        S1AP_PDU::InitiatingMessage(m) => (0, m.procedure_code.0),
        S1AP_PDU::SuccessfulOutcome(m) => (1, m.procedure_code.0),
        S1AP_PDU::UnsuccessfulOutcome(m) => (2, m.procedure_code.0),
    }
}

/// Decode with the generated codec, assert the CHOICE arm and procedure code,
/// and re-encode byte for byte.
fn round_trip(bytes: &[u8], expect: (u8, u8)) {
    let pdu = decode(bytes).unwrap_or_else(|e| panic!("generated decode failed: {e:?}"));
    assert_eq!(shape(&pdu), expect, "wrong CHOICE arm / procedure code");
    assert_eq!(encode(&pdu).unwrap(), bytes, "generated re-encode differs");
    let (again, unknown) = decode_with_unknown_ies(bytes).unwrap();
    assert_eq!(again, pdu);
    assert!(
        unknown.is_empty(),
        "a schema IE was reported unknown: {unknown:?}"
    );
}

#[test]
fn the_x691_golden_forms_decode_and_re_encode_byte_for_byte() {
    round_trip(&unhex(S1_SETUP_REQUEST), (0, 17));
    round_trip(&unhex(S1_SETUP_RESPONSE), (1, 17));
    round_trip(&unhex(S1_SETUP_FAILURE), (2, 17));
    round_trip(&unhex(INITIAL_UE_MESSAGE), (0, 12));
    round_trip(&unhex(DOWNLINK_NAS_TRANSPORT), (0, 11));
    round_trip(&unhex(UPLINK_NAS_TRANSPORT), (0, 13));
    round_trip(&unhex(INITIAL_CONTEXT_SETUP_REQUEST), (0, 9));
}

/// #455's exact defect: the value of an extensible message SEQUENCE without its
/// leading extension bit. The generated decoder must refuse the pre-#456 form
/// rather than read it shifted.
#[test]
fn the_pre_456_form_without_the_extension_bit_is_refused() {
    // S1 Setup Failure as pre-#456 nextgcore wrote it: the `00` extension
    // octet is missing, so the IE count lands where the extension bit belongs.
    let broken = unhex("4011000c000200024001450041400130");
    assert!(decode(&broken).is_err(), "pre-#456 bytes decoded");
}

const PLMN: [u8; 3] = [0x99, 0xf9, 0x07];

fn tai() -> Tai {
    Tai {
        plmn_identity: PLMN,
        tac: 1,
    }
}

fn cgi() -> EutranCgi {
    EutranCgi {
        plmn_identity: PLMN,
        cell_identity: 0x019B_0100,
    }
}

#[test]
fn hand_written_s1_setup_messages_agree_with_the_generated_codec() {
    for name_len in [1usize, 2, 3, 40, 150] {
        for gummeis in 1..=3usize {
            let bytes = build_s1_setup_response(&S1SetupResponse {
                mme_name: Some("m".repeat(name_len)),
                served_gummeis: (0..gummeis)
                    .map(|i| ServedGummeiItem {
                        served_plmns: vec![PLMN; i + 1],
                        served_group_ids: vec![2, 0xFFFF],
                        served_mmec_codes: vec![1, 0xFF],
                    })
                    .collect(),
                relative_mme_capacity: u8::try_from(name_len % 256).unwrap(),
            })
            .unwrap();
            round_trip(&bytes, (1, 17));
        }
    }
    for cause in [
        Cause::Misc(CauseMisc::UnknownPlmn),
        Cause::RadioNetwork(CauseRadioNetwork::Unspecified),
        Cause::Nas(CauseNas::NormalRelease),
    ] {
        for ttw in [None, Some(TimeToWait::V1s), Some(TimeToWait::V60s)] {
            let bytes = build_s1_setup_failure(&S1SetupFailure {
                cause,
                time_to_wait: ttw,
            })
            .unwrap();
            round_trip(&bytes, (2, 17));
        }
    }
}

#[test]
fn hand_written_nas_transport_agrees_with_the_generated_codec() {
    // 16,000 is near the hand-written encoder's ceiling: it has no X.691
    // §11.9.3.8 fragmentation and refuses an open type past 16,383 octets (see
    // `the_generated_codec_carries_a_nas_pdu_past_16k`).
    for len in [1usize, 2, 127, 128, 255, 1000, 16_000] {
        let nas = vec![0x5A; len];
        for ids in [(0u32, 0u32), (1, 1), (0xFF_FFFF, 0xFFFF_FFFF)] {
            round_trip(
                &build_downlink_nas_transport(&DlNasTransport {
                    mme_ue_s1ap_id: ids.1,
                    enb_ue_s1ap_id: ids.0,
                    nas_pdu: nas.clone(),
                })
                .unwrap(),
                (0, 11),
            );
            round_trip(
                &build_uplink_nas_transport(&UlNasTransport {
                    mme_ue_s1ap_id: ids.1,
                    enb_ue_s1ap_id: ids.0,
                    nas_pdu: nas.clone(),
                    eutran_cgi: cgi(),
                    tai: tai(),
                })
                .unwrap(),
                (0, 13),
            );
        }
        for s_tmsi in [
            None,
            Some(STmsi {
                mmec: 1,
                m_tmsi: 0xDEAD_BEEF,
            }),
        ] {
            round_trip(
                &build_initial_ue_message(&InitialUeMessage {
                    enb_ue_s1ap_id: 7,
                    nas_pdu: nas.clone(),
                    tai: tai(),
                    eutran_cgi: cgi(),
                    rrc_establishment_cause: RrcEstablishmentCause::MoSignalling,
                    s_tmsi,
                })
                .unwrap(),
                (0, 12),
            );
        }
    }
}

#[test]
fn hand_written_initial_context_setup_agrees_with_the_generated_codec() {
    for erabs in 1..=3u8 {
        for gbr in [false, true] {
            for nas in [None, Some(vec![0x27, 0x01, 0x02])] {
                let bytes = build_initial_context_setup_request(&InitialContextSetupRequest {
                    mme_ue_s1ap_id: 1,
                    enb_ue_s1ap_id: 1,
                    ue_ambr: UeAmbr {
                        dl: 10_000_000_000,
                        ul: 1,
                    },
                    erab_list: (0..erabs)
                        .map(|i| ErabToBeSetupItem {
                            erab_id: 5 + i,
                            erab_qos: ErabLevelQosParameters {
                                qci: if gbr { 1 } else { 9 },
                                arp: AllocationRetentionPriority {
                                    priority_level: 15,
                                    pre_emption_capability: true,
                                    pre_emption_vulnerability: true,
                                },
                                gbr_qos_info: gbr.then_some(GbrQosInformation {
                                    erab_max_bitrate_dl: 1_000_000,
                                    erab_max_bitrate_ul: 500_000,
                                    erab_guaranteed_bitrate_dl: 64_000,
                                    erab_guaranteed_bitrate_ul: 64_000,
                                }),
                            },
                            transport_layer_address: vec![10, 0, 0, 1 + i],
                            gtp_teid: 0x1000 + u32::from(i),
                            nas_pdu: nas.clone(),
                        })
                        .collect(),
                    ue_security_capabilities: UeSecurityCapabilities {
                        encryption_algorithms: 0xE000,
                        integrity_algorithms: 0x6000,
                    },
                    security_key: [0xA5; 32],
                })
                .unwrap();
                round_trip(&bytes, (0, 9));
            }
        }
    }
}

/// The hand-written encoder refuses a DL NAS Transport whose value needs a
/// length past 16,383 (`Invalid length`): it has no X.691 §11.9.3.8
/// fragmentation. The generated codec fragments (nextgsim #223), so a large
/// NAS-PDU round-trips, and the fragment header follows the procedure code and
/// criticality where §11.9.3.8 puts it.
#[test]
fn the_generated_codec_carries_a_nas_pdu_past_16k() {
    assert!(
        build_downlink_nas_transport(&DlNasTransport {
            mme_ue_s1ap_id: 1,
            enb_ue_s1ap_id: 1,
            nas_pdu: vec![0x5A; 16_383],
        })
        .is_err(),
        "the hand-written encoder now fragments; compare it byte for byte instead"
    );
    let small = decode(&unhex(DOWNLINK_NAS_TRANSPORT)).unwrap();
    let S1AP_PDU::InitiatingMessage(mut msg) = small else {
        panic!("not initiating")
    };
    let super::generated::InitiatingMessageValue::Id_downlinkNASTransport(ref mut v) = msg.value
    else {
        panic!("not DL NAS Transport")
    };
    for ie in &mut v.protocol_i_es.0 {
        if let super::generated::DownlinkNASTransportProtocolIEs_EntryValue::Id_NAS_PDU(nas) =
            &mut ie.value
        {
            nas.0 = vec![0x5A; 70_000];
        }
    }
    let pdu = S1AP_PDU::InitiatingMessage(msg);
    let bytes = encode(&pdu).unwrap();
    // CHOICE index 0 + procedure 11 + criticality ignore, then the open type's
    // first fragment header: 0b11 + m, m = 4 (64K) per §11.9.3.8.
    assert_eq!(&bytes[..3], &[0x00, 0x0b, 0x40]);
    assert_eq!(bytes[3], 0xC4);
    assert_eq!(decode(&bytes).unwrap(), pdu);
}
