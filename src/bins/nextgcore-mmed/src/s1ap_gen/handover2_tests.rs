//! #514 stage 8b: HANDOVER REQUIRED / REQUEST / REQUEST ACKNOWLEDGE / COMMAND
//! on the generated codec.
//!
//! Oracle: the pre-change hand-written builders and parser
//! (`test_codec::builder`, `decode_s1ap_pdu`: since #514 stage 13b the generated codec with an independently written domain mapping, and builders for messages mmed sends check that their output decodes back to their input). Golden: octets derived by
//! hand from X.691 (APER) for TS 36.413 §9.1.5.2.

use super::*;
use crate::context::{Bitrate, MmeContext, S1apCauseGroup};
use crate::s1ap_build::cause_to_s1ap;
use crate::s1ap_gen::test_codec::{builder, decode_s1ap_pdu};
use crate::s1ap_handler::handle_s1ap_message;
use nextgcore_s1ap::{
    AllocationRetentionPriority, CauseNas, CauseRadioNetwork, DirectForwardingPathAvailability,
    ErabAdmittedItem, ErabDataForwardingItem, ErabFailedItem, ErabItem, ErabLevelQosParameters,
    ErabToBeSetupItemHoReq, GbrQosInformation, HandoverCommand, HandoverRequest,
    HandoverRequestAcknowledge, HandoverRequired, HandoverType, S1apMessage, SecurityContext,
    TargetId, UeAmbr, UeSecurityCapabilities,
};

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// HANDOVER COMMAND, MME 1 / eNB 1, intralte, no lists, container `AB`:
/// `20 00 00 1a` (successful outcome: ext 0, index 01, pad; procedure 0;
/// reject; length 26), `00 00 04` (ext 0 + pad, four IEs), MME-UE-S1AP-ID
/// IE 0 at reject (`00 00 00`, length 2, `00 01`: 2-bit octet count 0 + pad,
/// value 1), eNB-UE-S1AP-ID IE 8 likewise, HandoverType IE 1 at reject
/// (length 1, `00`: ext 0, 3-bit index 0, pad), Target-ToSource container IE
/// 123 at reject (length 2, `01 ab`).
const COMMAND: &str = "2000001a0000040000000200010008000200010001000100007b000201ab";

#[test]
fn the_handover_command_is_the_x691_golden() {
    let cmd = build_handover_command(
        &HandoverCommand {
            mme_ue_s1ap_id: 1,
            enb_ue_s1ap_id: 1,
            handover_type: HandoverType::IntraLte,
            erab_subject_to_forwarding_list: vec![],
            erab_to_release_list: vec![],
            target_to_source_container: vec![0xAB],
        },
        &[],
    )
    .unwrap();
    assert_eq!(hex(&cmd), COMMAND);
}

const TYPES: [HandoverType; 7] = [
    HandoverType::IntraLte,
    HandoverType::LteToUtran,
    HandoverType::LteToGeran,
    HandoverType::UtranToLte,
    HandoverType::GeranToLte,
    HandoverType::EpsTo5gs,
    HandoverType::FiveGsToEps,
];

fn causes() -> Vec<Cause> {
    let mut out = Vec::new();
    for group in [
        S1apCauseGroup::RadioNetwork,
        S1apCauseGroup::Transport,
        S1apCauseGroup::Nas,
        S1apCauseGroup::Protocol,
        S1apCauseGroup::Misc,
    ] {
        for value in 0..48 {
            let c = cause_to_s1ap(group, value);
            if !out.contains(&c) {
                out.push(c);
            }
        }
    }
    out
}

fn addr(i: usize) -> Vec<u8> {
    if i.is_multiple_of(2) {
        vec![10, 0, 0, i as u8]
    } else {
        (0u8..16).collect()
    }
}

fn setup_items(n: usize) -> Vec<ErabToBeSetupItemHoReq> {
    (0..n)
        .map(|i| ErabToBeSetupItemHoReq {
            erab_id: 5 + i as u8,
            transport_layer_address: addr(i),
            gtp_teid: 0x8000_0000 + i as u32,
            erab_qos: ErabLevelQosParameters {
                qci: 1 + (i as u8 % 9),
                arp: AllocationRetentionPriority {
                    priority_level: 1 + i as u8,
                    pre_emption_capability: i.is_multiple_of(2),
                    pre_emption_vulnerability: i.is_multiple_of(3),
                },
                gbr_qos_info: (i % 2 == 1).then_some(GbrQosInformation {
                    erab_max_bitrate_dl: 10_000_000_000,
                    erab_max_bitrate_ul: 1,
                    erab_guaranteed_bitrate_dl: 0,
                    erab_guaranteed_bitrate_ul: 64_000,
                }),
            },
        })
        .collect()
}

#[test]
fn the_handover_request_matches_the_hand_written_encoder() {
    let mut cases = 0;
    for ty in TYPES {
        for cause in causes() {
            for n in [1usize, 3] {
                for container in [vec![0x01], (0..200u8).collect::<Vec<_>>()] {
                    let req = HandoverRequest {
                        mme_ue_s1ap_id: 0xFFFF_FFFF,
                        handover_type: ty,
                        cause,
                        ue_ambr: UeAmbr {
                            dl: 10_000_000_000,
                            ul: 0,
                        },
                        erab_list: setup_items(n),
                        source_to_target_container: container,
                        ue_security_capabilities: UeSecurityCapabilities {
                            encryption_algorithms: 0xE000,
                            integrity_algorithms: 0x6000,
                        },
                        security_context: SecurityContext {
                            next_hop_chaining_count: (cases % 8) as u8,
                            next_hop_parameter: [0xA5; 32],
                        },
                    };
                    assert_eq!(
                        hex(&build_handover_request(&req).unwrap()),
                        hex(&builder::build_handover_request(&req).unwrap()),
                        "{req:?}"
                    );
                    cases += 1;
                }
            }
        }
    }
    assert!(cases > 1000, "{cases}");
}

fn forwarding(n: usize) -> Vec<ErabDataForwardingItem> {
    (0..n)
        .map(|i| ErabDataForwardingItem {
            erab_id: 5 + i as u8,
            dl_transport_layer_address: (i % 4 != 1).then(|| addr(i)),
            dl_gtp_teid: (i % 4 != 2).then_some(0x10 + i as u32),
            ul_transport_layer_address: (i.is_multiple_of(4)).then(|| addr(i + 1)),
            ul_gtp_teid: (i.is_multiple_of(4)).then_some(0x20 + i as u32),
        })
        .collect()
}

#[test]
fn the_handover_command_matches_the_hand_written_encoder() {
    let mut cases = 0;
    for ty in TYPES {
        for (mme, enb) in [(0, 0), (1, 1), (0xFFFF_FFFF, 0xFF_FFFF)] {
            for nf in [0usize, 1, 4] {
                for nr in [0usize, 1, 3] {
                    let cmd = HandoverCommand {
                        mme_ue_s1ap_id: mme,
                        enb_ue_s1ap_id: enb,
                        handover_type: ty,
                        erab_subject_to_forwarding_list: forwarding(nf),
                        erab_to_release_list: causes()
                            .into_iter()
                            .take(nr)
                            .enumerate()
                            .map(|(i, cause)| ErabItem {
                                erab_id: 9 + i as u8,
                                cause,
                            })
                            .collect(),
                        target_to_source_container: vec![0xBE, 0xEF],
                    };
                    assert_eq!(
                        hex(&build_handover_command(&cmd, &[]).unwrap()),
                        hex(&builder::build_handover_command(&cmd).unwrap()),
                        "{cmd:?}"
                    );
                    cases += 1;
                }
            }
        }
    }
    assert_eq!(cases, 7 * 3 * 3 * 3);
}

fn targets() -> Vec<TargetId> {
    let plmn = [0x13, 0x00, 0x14];
    let tai = nextgcore_s1ap::Tai {
        plmn_identity: plmn,
        tac: 0xFFFE,
    };
    vec![
        TargetId::TargetEnbId {
            global_enb_id: GlobalEnbId {
                plmn_identity: plmn,
                enb_id: EnbId::Macro(0xF_FFFF),
            },
            selected_tai: tai.clone(),
        },
        TargetId::TargetEnbId {
            global_enb_id: GlobalEnbId {
                plmn_identity: plmn,
                enb_id: EnbId::Home(0xFFF_FFFF),
            },
            selected_tai: tai,
        },
        TargetId::TargetRncId {
            plmn_identity: plmn,
            lac: 0x1234,
            rac: None,
            rnc_id: 4095,
        },
        TargetId::TargetRncId {
            plmn_identity: plmn,
            lac: 0x1234,
            rac: Some(7),
            rnc_id: 0,
        },
        TargetId::Cgi {
            plmn_identity: plmn,
            lac: 1,
            ci: 0xFFFF,
            rac: None,
        },
        TargetId::Cgi {
            plmn_identity: plmn,
            lac: 1,
            ci: 2,
            rac: Some(0xFF),
        },
    ]
}

fn required(target_id: TargetId, ty: HandoverType, cause: Cause, direct: bool) -> HandoverRequired {
    HandoverRequired {
        mme_ue_s1ap_id: 0xFFFF_FFFF,
        enb_ue_s1ap_id: 0xFF_FFFF,
        handover_type: ty,
        cause,
        target_id,
        direct_forwarding_path_availability: direct
            .then_some(DirectForwardingPathAvailability::DirectPathAvailable),
        source_to_target_container: vec![0xDE, 0xAD],
    }
}

#[test]
fn the_handover_required_decodes_as_the_hand_written_parser_reads_it() {
    let mut cases = 0;
    for target in targets() {
        for ty in TYPES {
            for cause in causes() {
                for direct in [false, true] {
                    let bytes = builder::build_handover_required(&required(
                        target.clone(),
                        ty,
                        cause,
                        direct,
                    ))
                    .unwrap();
                    let Ok(S1apMessage::HandoverRequired(old)) = decode_s1ap_pdu(&bytes) else {
                        panic!("the oracle refused its own encoding");
                    };
                    let HandoverRequiredDecode::Proceed { msg, notify } =
                        decode_handover_required(&bytes)
                    else {
                        panic!("{old:?}");
                    };
                    assert!(notify.is_empty());
                    assert_eq!(format!("{msg:?}"), format!("{old:?}"));
                    cases += 1;
                }
            }
        }
    }
    assert!(cases > 4000, "{cases}");
}

fn admitted(n: usize) -> Vec<ErabAdmittedItem> {
    (0..n)
        .map(|i| ErabAdmittedItem {
            erab_id: 5 + i as u8,
            transport_layer_address: addr(i),
            gtp_teid: 0xFFFF_FF00 + i as u32,
            dl_transport_layer_address: (i % 3 != 1).then(|| addr(i + 1)),
            dl_gtp_teid: (i % 3 != 2).then_some(i as u32),
            ul_transport_layer_address: (i.is_multiple_of(3)).then(|| addr(i)),
            ul_gtp_teid: (i.is_multiple_of(3)).then_some(0xABCD),
        })
        .collect()
}

fn ack(n: usize, failed: usize) -> HandoverRequestAcknowledge {
    HandoverRequestAcknowledge {
        mme_ue_s1ap_id: 0xFFFF_FFFF,
        enb_ue_s1ap_id: 0xFF_FFFF,
        erab_admitted_list: admitted(n),
        erab_failed_list: causes()
            .into_iter()
            .take(failed)
            .enumerate()
            .map(|(i, cause)| ErabFailedItem {
                erab_id: 12 + (i as u8 % 3),
                cause,
            })
            .collect(),
        target_to_source_container: (0..150u8).collect(),
    }
}

#[test]
fn the_handover_request_acknowledge_decodes_as_the_hand_written_parser_reads_it() {
    let mut cases = 0;
    for n in [1usize, 2, 3, 6] {
        for failed in [0usize, 1, 3] {
            let bytes = builder::build_handover_request_acknowledge(&ack(n, failed)).unwrap();
            let Ok(S1apMessage::HandoverRequestAcknowledge(old)) = decode_s1ap_pdu(&bytes) else {
                panic!("oracle");
            };
            let ResponseDecode::Decoded { msg, notify } =
                decode_handover_request_acknowledge(&bytes)
            else {
                panic!("{old:?}");
            };
            assert!(notify.is_empty());
            assert_eq!(format!("{msg:?}"), format!("{old:?}"));
            cases += 1;
        }
    }
    assert_eq!(cases, 12);
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

/// Remove the IE with `id` (one-octet open-type lengths) from a message.
fn remove(msg: &[u8], id: u16) -> Vec<u8> {
    let body = &msg[4..];
    let count = u16::from_be_bytes([body[1], body[2]]);
    let mut ies = Vec::new();
    let mut at = 3;
    for _ in 0..count {
        let ie_id = u16::from_be_bytes([body[at], body[at + 1]]);
        let end = at + 4 + usize::from(body[at + 3]);
        if ie_id != id {
            ies.extend_from_slice(&body[at..end]);
        }
        at = end;
    }
    let mut value = vec![body[0]];
    value.extend_from_slice(&(count - 1).to_be_bytes());
    value.extend_from_slice(&ies);
    let mut out = vec![msg[0], msg[1], msg[2], u8::try_from(value.len()).unwrap()];
    out.extend_from_slice(&value);
    out
}

fn small_required() -> Vec<u8> {
    builder::build_handover_required(&required(
        targets().remove(0),
        HandoverType::IntraLte,
        Cause::RadioNetwork(CauseRadioNetwork::HandoverDesirableForRadioReason),
        false,
    ))
    .unwrap()
}

fn small_ack() -> Vec<u8> {
    let mut a = ack(1, 0);
    a.target_to_source_container = vec![0x01];
    builder::build_handover_request_acknowledge(&a).unwrap()
}

#[test]
fn the_handover_required_is_handled_by_criticality() {
    let r = small_required();
    // Each `reject` IE, missing, rejects; a missing Cause (`ignore`) does not.
    for id in [
        ID_MME_UE_S1AP_ID,
        ID_ENB_UE_S1AP_ID,
        ID_HANDOVER_TYPE,
        ID_TARGET_ID,
        ID_SOURCE_TO_TARGET_CONTAINER,
    ] {
        assert!(
            matches!(
                decode_handover_required(&remove(&r, id)),
                HandoverRequiredDecode::Reject { ies, .. }
                    if ies == [DiagnosedIe { criticality: REJECT, id, type_of_error: g::TypeOfError::MISSING }]
            ),
            "missing IE {id}"
        );
    }
    let HandoverRequiredDecode::Proceed { msg, .. } =
        decode_handover_required(&remove(&r, ID_CAUSE))
    else {
        panic!("a missing Cause must not stop the procedure");
    };
    assert_eq!(
        msg.cause,
        Cause::RadioNetwork(CauseRadioNetwork::Unspecified)
    );
    assert!(matches!(
        decode_handover_required(&splice(&r, 9999, REJECT)),
        HandoverRequiredDecode::Reject { ies, .. } if ies[0].id == 9999
    ));
    assert!(matches!(
        decode_handover_required(&splice(&r, 9999, NOTIFY)),
        HandoverRequiredDecode::Proceed { notify, .. } if notify[0].id == 9999
    ));
    assert!(matches!(
        decode_handover_required(&splice(&r, 9999, IGNORE)),
        HandoverRequiredDecode::Proceed { notify, .. } if notify.is_empty()
    ));
}

#[test]
fn an_ng_ran_target_is_an_unsupported_target_not_a_decode_error() {
    let Ok(g::S1AP_PDU::InitiatingMessage(mut msg)) = nextgcore_s1ap_gen::decode(&small_required())
    else {
        panic!("decode");
    };
    let g::InitiatingMessageValue::Id_HandoverPreparation(ref mut m) = msg.value else {
        panic!("value");
    };
    for ie in &mut m.protocol_i_es.0 {
        if let g::HandoverRequiredProtocolIEs_EntryValue::Id_TargetID(t) = &mut ie.value {
            *t = g::TargetID::TargetgNgRanNode_ID(g::TargetNgRanNode_ID {
                global_ran_node_id: g::Global_RAN_NODE_ID::GNB(g::GNB {
                    global_g_nb_id: g::Global_GNB_ID {
                        plmn_identity: g::TBCD_STRING(vec![0x13, 0x00, 0x14]),
                        gnb_id: g::GNB_Identity::GNB_ID(g::GNB_ID(u32_to_bits(1, 22))),
                        ie_extensions: None,
                    },
                    ie_extensions: None,
                }),
                selected_tai: g::FiveGSTAI {
                    plm_nidentity: g::TBCD_STRING(vec![0x13, 0x00, 0x14]),
                    five_gstac: g::FiveGSTAC(vec![0, 0, 1]),
                    ie_extensions: None,
                },
                ie_extensions: None,
            });
        }
    }
    let bytes = nextgcore_s1ap_gen::encode(&g::S1AP_PDU::InitiatingMessage(msg)).unwrap();
    // The hand-written parser refused the whole message.
    assert!(decode_s1ap_pdu(&bytes).is_err());
    assert!(matches!(
        decode_handover_required(&bytes),
        HandoverRequiredDecode::UnsupportedTarget {
            mme_ue_s1ap_id: 0xFFFF_FFFF,
            enb_ue_s1ap_id: 0xFF_FFFF
        }
    ));
    // Through the handler: HANDOVER PREPARATION FAILURE, unknown-targetID.
    let ctx = MmeContext::new();
    let enb = ctx.enb_add("127.0.0.1:36412".parse().unwrap());
    let out = handle_s1ap_message(&ctx, enb, &bytes);
    assert_eq!(out.len(), 1);
    let Ok(S1apMessage::HandoverPreparationFailure(f)) = decode_s1ap_pdu(&out[0].pdu) else {
        panic!("expected a Handover Preparation Failure");
    };
    assert_eq!(
        f.cause,
        Cause::RadioNetwork(CauseRadioNetwork::UnknownTargetId)
    );
}

#[test]
fn the_acknowledge_is_handled_by_criticality() {
    let a = small_ack();
    // The container is `reject`: missing, the response is handled locally.
    assert!(matches!(
        decode_handover_request_acknowledge(&remove(&a, ID_TARGET_TO_SOURCE_CONTAINER)),
        ResponseDecode::Failed(ies) if ies[0].id == ID_TARGET_TO_SOURCE_CONTAINER
    ));
    // The admitted list is `ignore`: missing, it reads as empty.
    let ResponseDecode::Decoded { msg, .. } =
        decode_handover_request_acknowledge(&remove(&a, ID_ERAB_ADMITTED_LIST))
    else {
        panic!("a missing ignore IE must not stop the response");
    };
    assert!(msg.erab_admitted_list.is_empty());
    assert!(matches!(
        decode_handover_request_acknowledge(&splice(&a, 9999, REJECT)),
        ResponseDecode::Failed(_)
    ));
    assert!(matches!(
        decode_handover_request_acknowledge(&splice(&a, 9999, NOTIFY)),
        ResponseDecode::Decoded { notify, .. } if notify[0].id == 9999
    ));
}

/// A source UE with one bearer and a target eNB with eNB ID 0x2222; returns
/// (ctx, source eNB, target eNB, source MME-UE-S1AP-ID).
fn handover_ctx() -> (MmeContext, u64, u64, u32) {
    let ctx = MmeContext::new();
    let source = ctx.enb_add("127.0.0.1:36412".parse().unwrap());
    let enb_ue_id = ctx.enb_ue_add(source, 100);
    let mme_ue_id = ctx.mme_ue_add(enb_ue_id);
    ctx.enb_ue_associate_mme_ue(enb_ue_id, mme_ue_id);
    let mme = ctx.enb_ue_find_by_id(enb_ue_id).unwrap().mme_ue_s1ap_id;
    {
        let mut pool = ctx.mme_ue_pool.write().unwrap();
        let ue = pool.get_mut(&mme_ue_id).unwrap();
        ue.kasme = [0x11; 32];
        ue.kenb = [0x22; 32];
        ue.ambr = Bitrate {
            downlink: 1_000_000,
            uplink: 500_000,
        };
    }
    let bearer_id = ctx.bearer_add(0, mme_ue_id);
    {
        let mut pool = ctx.bearer_pool.write().unwrap();
        let b = pool.get_mut(&bearer_id).unwrap();
        b.ebi = 5;
        b.sgw_s1u_teid = 0x5555;
        b.sgw_s1u_ip.ipv4 = Some([10, 0, 0, 2]);
        b.qos.qci = 9;
        b.qos.arp.priority_level = 8;
    }
    let target = ctx.enb_add("127.0.0.8:36412".parse().unwrap());
    ctx.enb_set_enb_id(target, 0x2222);
    (ctx, source, target, mme)
}

fn required_for(mme: u32) -> Vec<u8> {
    builder::build_handover_required(&HandoverRequired {
        mme_ue_s1ap_id: mme,
        enb_ue_s1ap_id: 100,
        handover_type: HandoverType::IntraLte,
        cause: Cause::RadioNetwork(CauseRadioNetwork::HandoverDesirableForRadioReason),
        target_id: TargetId::TargetEnbId {
            global_enb_id: GlobalEnbId {
                plmn_identity: [0x13, 0x00, 0x14],
                enb_id: EnbId::Macro(0x2222),
            },
            selected_tai: nextgcore_s1ap::Tai {
                plmn_identity: [0x13, 0x00, 0x14],
                tac: 2,
            },
        },
        direct_forwarding_path_availability: None,
        source_to_target_container: vec![0x01],
    })
    .unwrap()
}

fn ack_for(target_mme: u32) -> Vec<u8> {
    builder::build_handover_request_acknowledge(&HandoverRequestAcknowledge {
        mme_ue_s1ap_id: target_mme,
        enb_ue_s1ap_id: 300,
        erab_admitted_list: vec![ErabAdmittedItem {
            erab_id: 5,
            transport_layer_address: vec![10, 0, 0, 8],
            gtp_teid: 0x8888,
            dl_transport_layer_address: None,
            dl_gtp_teid: None,
            ul_transport_layer_address: None,
            ul_gtp_teid: None,
        }],
        erab_failed_list: vec![],
        target_to_source_container: vec![0xBE, 0xEF],
    })
    .unwrap()
}

#[test]
fn through_the_handler_a_notify_ie_in_the_required_reaches_the_command() {
    let (ctx, source, target, mme) = handover_ctx();
    let out = handle_s1ap_message(&ctx, source, &splice(&required_for(mme), 9999, NOTIFY));
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].enb_id, target);
    let Ok(S1apMessage::HandoverRequest(req)) = decode_s1ap_pdu(&out[0].pdu) else {
        panic!("expected a Handover Request");
    };
    let out = handle_s1ap_message(&ctx, target, &ack_for(req.mme_ue_s1ap_id));
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].enb_id, source);
    let Ok(g::S1AP_PDU::SuccessfulOutcome(g::SuccessfulOutcome {
        value: g::SuccessfulOutcomeValue::Id_HandoverPreparation(cmd),
        ..
    })) = nextgcore_s1ap_gen::decode(&out[0].pdu)
    else {
        panic!("expected a Handover Command");
    };
    let diag = cmd
        .protocol_i_es
        .0
        .iter()
        .find_map(|ie| match &ie.value {
            g::HandoverCommandProtocolIEs_EntryValue::Id_CriticalityDiagnostics(d) => {
                Some(d.clone())
            }
            _ => None,
        })
        .expect("the command must carry the required's notify IE");
    assert_eq!(
        diag.procedure_code,
        Some(g::ProcedureCode(PROC_HANDOVER_PREPARATION))
    );
    assert_eq!(
        diag.i_es_criticality_diagnostics.unwrap().0[0].ie_id,
        g::ProtocolIE_ID(9999)
    );
}

#[test]
fn through_the_handler_a_reject_ie_gets_a_preparation_failure_naming_it() {
    let (ctx, source, _, mme) = handover_ctx();
    let out = handle_s1ap_message(&ctx, source, &remove(&required_for(mme), ID_TARGET_ID));
    assert_eq!(out.len(), 1);
    let Ok(g::S1AP_PDU::UnsuccessfulOutcome(g::UnsuccessfulOutcome {
        value: g::UnsuccessfulOutcomeValue::Id_HandoverPreparation(f),
        ..
    })) = nextgcore_s1ap_gen::decode(&out[0].pdu)
    else {
        panic!("expected a Handover Preparation Failure");
    };
    let diag = f
        .protocol_i_es
        .0
        .iter()
        .find_map(|ie| match &ie.value {
            g::HandoverPreparationFailureProtocolIEs_EntryValue::Id_CriticalityDiagnostics(d) => {
                Some(d.clone())
            }
            _ => None,
        })
        .expect("diagnostics");
    let item = &diag.i_es_criticality_diagnostics.unwrap().0[0];
    assert_eq!(item.ie_id, g::ProtocolIE_ID(ID_TARGET_ID));
    assert_eq!(item.type_of_error, g::TypeOfError(g::TypeOfError::MISSING));
}

#[test]
fn through_the_handler_an_acknowledge_without_its_container_sends_no_command() {
    let (ctx, source, target, mme) = handover_ctx();
    let out = handle_s1ap_message(&ctx, source, &required_for(mme));
    let Ok(S1apMessage::HandoverRequest(req)) = decode_s1ap_pdu(&out[0].pdu) else {
        panic!("expected a Handover Request");
    };
    let out = handle_s1ap_message(
        &ctx,
        target,
        &remove(&ack_for(req.mme_ue_s1ap_id), ID_TARGET_TO_SOURCE_CONTAINER),
    );
    assert!(out.is_empty(), "{out:?}");
}

#[test]
fn a_notify_in_a_preparation_failure_is_reported_too() {
    // No bearer for the UE: the MME answers HANDOVER PREPARATION FAILURE, and
    // the required's notify IE is reported in it.
    let ctx = MmeContext::new();
    let enb = ctx.enb_add("127.0.0.1:36412".parse().unwrap());
    let out = handle_s1ap_message(&ctx, enb, &splice(&required_for(4242), 9999, NOTIFY));
    assert_eq!(out.len(), 1);
    let Ok(g::S1AP_PDU::UnsuccessfulOutcome(g::UnsuccessfulOutcome {
        value: g::UnsuccessfulOutcomeValue::Id_HandoverPreparation(f),
        ..
    })) = nextgcore_s1ap_gen::decode(&out[0].pdu)
    else {
        panic!("expected a Handover Preparation Failure");
    };
    assert!(f.protocol_i_es.0.iter().any(|ie| matches!(
        &ie.value,
        g::HandoverPreparationFailureProtocolIEs_EntryValue::Id_CriticalityDiagnostics(_)
    )));
    let _ = CauseNas::Unspecified;
}
