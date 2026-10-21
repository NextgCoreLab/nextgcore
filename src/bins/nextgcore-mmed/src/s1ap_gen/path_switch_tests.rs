//! #514 stage 10: Path Switch on the generated codec.
//!
//! Oracle: the pre-change hand-written builders and parser
//! (`test_codec::builder`, `decode_s1ap_pdu`: since #514 stage 13b the generated codec with an independently written domain mapping, and builders for messages mmed sends check that their output decodes back to their input). Golden: octets derived by
//! hand from X.691 (APER) for TS 36.413 §9.1.5.10.

use super::*;
use crate::context::{MmeContext, S1apCauseGroup};
use crate::s1ap_build::cause_to_s1ap;
use crate::s1ap_gen::test_codec::{builder, decode_s1ap_pdu};
use crate::s1ap_handler::handle_s1ap_message;
use nextgcore_s1ap::{
    CauseNas, ErabSwitchedItem, PathSwitchRequest, PathSwitchRequestAcknowledge,
    PathSwitchRequestFailure, S1apMessage, SecurityContext, UeSecurityCapabilities,
};

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// PATH SWITCH REQUEST FAILURE, MME 1 / eNB 1, Cause nas / normal-release:
/// `40 03 00 14` (unsuccessful outcome, procedure 3, reject, length 20),
/// `00 00 03`, the two IDs at ignore (`40`, length 2, `00 01`), Cause IE 2 at
/// ignore, `0 010 0 00` and pad = `20`.
const FAILURE: &str = "400300140000030000400200010008400200010002400120";

#[test]
fn the_failure_is_the_x691_golden() {
    let f = build_path_switch_request_failure(
        &PathSwitchRequestFailure {
            mme_ue_s1ap_id: 1,
            enb_ue_s1ap_id: 1,
            cause: Cause::Nas(CauseNas::NormalRelease),
        },
        &[],
    )
    .unwrap();
    assert_eq!(hex(&f), FAILURE);
}

const IDS: [(u32, u32); 3] = [(0, 0), (1, 1), (0xFFFF_FFFF, 0xFF_FFFF)];

fn switched(n: usize) -> Vec<ErabSwitchedItem> {
    (0..n)
        .map(|i| ErabSwitchedItem {
            erab_id: 5 + i as u8,
            transport_layer_address: if i % 2 == 0 {
                vec![10, 0, 0, i as u8]
            } else {
                (0u8..16).collect()
            },
            gtp_teid: 0x8000_0000 + i as u32,
        })
        .collect()
}

#[test]
fn the_acknowledge_and_failure_match_the_hand_written_encoder() {
    let mut cases = 0;
    for (mme, enb) in IDS {
        for n in [0usize, 1, 3] {
            for ncc in 0u8..8 {
                for nh in [[0u8; 32], [0xA5; 32]] {
                    let ack = PathSwitchRequestAcknowledge {
                        mme_ue_s1ap_id: mme,
                        enb_ue_s1ap_id: enb,
                        erab_switched_ul_list: switched(n),
                        security_context: SecurityContext {
                            next_hop_chaining_count: ncc,
                            next_hop_parameter: nh,
                        },
                    };
                    assert_eq!(
                        hex(&build_path_switch_request_acknowledge(&ack, &[]).unwrap()),
                        hex(&builder::build_path_switch_request_acknowledge(&ack).unwrap()),
                        "{ack:?}"
                    );
                    cases += 1;
                }
            }
        }
        for group in [
            S1apCauseGroup::RadioNetwork,
            S1apCauseGroup::Transport,
            S1apCauseGroup::Nas,
            S1apCauseGroup::Protocol,
            S1apCauseGroup::Misc,
        ] {
            for value in 0..48 {
                let f = PathSwitchRequestFailure {
                    mme_ue_s1ap_id: mme,
                    enb_ue_s1ap_id: enb,
                    cause: cause_to_s1ap(group, value),
                };
                assert_eq!(
                    hex(&build_path_switch_request_failure(&f, &[]).unwrap()),
                    hex(&builder::build_path_switch_request_failure(&f).unwrap())
                );
                cases += 1;
            }
        }
    }
    assert!(cases > 800, "{cases}");
}

fn request(enb: u32, mme: u32, n: usize, algs: (u16, u16)) -> PathSwitchRequest {
    PathSwitchRequest {
        enb_ue_s1ap_id: enb,
        erab_switched_dl_list: switched(n),
        source_mme_ue_s1ap_id: mme,
        eutran_cgi: EutranCgi {
            plmn_identity: [0x99, 0xF9, 0x07],
            cell_identity: 0x0ABC_DEF1,
        },
        tai: Tai {
            plmn_identity: [0x99, 0xF9, 0x07],
            tac: 7,
        },
        ue_security_capabilities: UeSecurityCapabilities {
            encryption_algorithms: algs.0,
            integrity_algorithms: algs.1,
        },
    }
}

#[test]
fn the_request_decodes_as_the_hand_written_parser_reads_it() {
    for (mme, enb) in IDS {
        for n in [1usize, 2, 8] {
            for algs in [(0, 0), (0xE000, 0x6000), (0xFFFF, 0xFFFF)] {
                let bytes =
                    builder::build_path_switch_request(&request(enb, mme, n, algs)).unwrap();
                let S1apMessage::PathSwitchRequest(old) = decode_s1ap_pdu(&bytes).unwrap() else {
                    panic!("oracle");
                };
                let Class2Decode::Proceed { msg, notify } = decode_path_switch_request(&bytes)
                else {
                    panic!("{mme} {enb} {n}");
                };
                assert!(notify.is_empty());
                assert_eq!(
                    format!("{msg:?}"),
                    format!("{:?}", PathSwitchRequestAt::from(&old))
                );
            }
        }
    }
}

/// Splice an unknown IE after the IE count (one-octet open-type length).
fn splice(msg: &[u8], id: u16, criticality: u8) -> Vec<u8> {
    let len = usize::from(msg[3]);
    assert!(len < 0x7F);
    let body = &msg[4..];
    let count = u16::from_be_bytes([body[1], body[2]]) + 1;
    let ie = [(id >> 8) as u8, id as u8, criticality << 6, 0x01, 0x00];
    let mut out = vec![
        msg[0],
        msg[1],
        msg[2],
        u8::try_from(len + ie.len()).unwrap(),
        body[0],
    ];
    out.extend_from_slice(&count.to_be_bytes());
    out.extend_from_slice(&ie);
    out.extend_from_slice(&body[3..]);
    out
}

fn small_request() -> Vec<u8> {
    builder::build_path_switch_request(&request(1, 1, 1, (0xE000, 0x6000))).unwrap()
}

#[test]
fn unknown_ies_in_the_request_are_handled_by_criticality() {
    assert!(matches!(
        decode_path_switch_request(&splice(&small_request(), 9999, IGNORE)),
        Class2Decode::Proceed { notify, .. } if notify.is_empty()
    ));
    assert!(matches!(
        decode_path_switch_request(&splice(&small_request(), 9999, NOTIFY)),
        Class2Decode::Proceed { notify, .. } if notify[0].id == 9999
    ));
    assert!(matches!(
        decode_path_switch_request(&splice(&small_request(), 9999, REJECT)),
        Class2Decode::Reject { ies, mme_ue_s1ap_id: Some(1), enb_ue_s1ap_id: Some(1) }
            if ies[0].id == 9999
    ));
}

#[test]
fn through_the_handler_a_reject_ie_gets_a_failure_naming_it() {
    let ctx = MmeContext::new();
    let enb = ctx.enb_add("127.0.0.1:36412".parse().unwrap());
    let out = handle_s1ap_message(&ctx, enb, &splice(&small_request(), 9999, REJECT));
    assert_eq!(out.len(), 1);
    let Ok(g::S1AP_PDU::UnsuccessfulOutcome(g::UnsuccessfulOutcome {
        value: g::UnsuccessfulOutcomeValue::Id_PathSwitchRequest(f),
        ..
    })) = nextgcore_s1ap_gen::decode(&out[0].pdu)
    else {
        panic!("expected Path Switch Request Failure");
    };
    let diag = f
        .protocol_i_es
        .0
        .iter()
        .find_map(|ie| match &ie.value {
            g::PathSwitchRequestFailureProtocolIEs_EntryValue::Id_CriticalityDiagnostics(d) => {
                Some(d.clone())
            }
            _ => None,
        })
        .expect("the failure must carry Criticality Diagnostics");
    assert_eq!(
        diag.i_es_criticality_diagnostics.unwrap().0[0].ie_id,
        g::ProtocolIE_ID(9999)
    );
}

#[test]
fn a_notify_ie_appears_in_the_acknowledge() {
    let ack = build_path_switch_request_acknowledge(
        &PathSwitchRequestAcknowledge {
            mme_ue_s1ap_id: 1,
            enb_ue_s1ap_id: 1,
            erab_switched_ul_list: vec![],
            security_context: SecurityContext {
                next_hop_chaining_count: 1,
                next_hop_parameter: [0; 32],
            },
        },
        &[DiagnosedIe {
            criticality: NOTIFY,
            id: 9999,
            type_of_error: g::TypeOfError::NOT_UNDERSTOOD,
        }],
    )
    .unwrap();
    let Ok(g::S1AP_PDU::SuccessfulOutcome(g::SuccessfulOutcome {
        value: g::SuccessfulOutcomeValue::Id_PathSwitchRequest(a),
        ..
    })) = nextgcore_s1ap_gen::decode(&ack)
    else {
        panic!("acknowledge");
    };
    assert!(a.protocol_i_es.0.iter().any(|ie| matches!(
        &ie.value,
        g::PathSwitchRequestAcknowledgeProtocolIEs_EntryValue::Id_CriticalityDiagnostics(_)
    )));
}
