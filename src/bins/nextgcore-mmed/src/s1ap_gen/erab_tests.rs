//! #514 stage 6: E-RAB management on the generated codec.
//!
//! #737: since the hand-written encoder was deleted (#560), the
//! `*_with_schema_criticalities` tests below compare the production encoder
//! with itself and check it decodes back; what pins each IE criticality is
//! `criticality_oracle`, which checks every PDU a production builder encodes
//! against the TS 36.413 §9.3 object sets.
//!
//! Oracle: the pre-change hand-written builders and parser
//! (`test_codec::builder`, `decode_s1ap_pdu`: since #514 stage 13b the generated codec with an independently written domain mapping, and builders for messages mmed sends check that their output decodes back to their input). Golden: octets derived by
//! hand from X.691 (APER) for TS 36.413 §9.1.3.5.

use super::*;
use crate::context::{MmeContext, S1apCauseGroup};
use crate::s1ap_build::cause_to_s1ap;
use crate::s1ap_gen::test_codec::{builder, decode_s1ap_pdu};
use crate::s1ap_handler::handle_s1ap_message;
use nextgcore_s1ap::{
    AllocationRetentionPriority, CauseNas, ErabFailedItem, ErabItem, ErabLevelQosParameters,
    ErabModifyRequest, ErabModifyResponse, ErabReleaseCommand, ErabReleaseResponse, ErabSetupItem,
    ErabSetupRequest, ErabSetupResponse, ErabToBeModifiedItem, ErabToBeSetupItem,
    GbrQosInformation, S1apMessage, UeAmbr,
};

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// E-RAB RELEASE COMMAND, MME 1 / eNB 1, release E-RAB 5 cause nas / detach,
/// no UE-AMBR, no NAS-PDU.
///
/// `00 07 00` initiatingMessage, procedure 7, criticality reject; open-type
/// length `1a` (26). Value: `00` SEQUENCE ext bit + pad, `00 03` three IEs.
/// IE 0 `00 00 | 00 | 02 | 00 01` (reject; MME-UE-S1AP-ID 1-octet length `00`
/// and pad, then `01`); IE 8 `00 08 | 00 | 02 | 00 01` likewise. IE 33
/// `00 21 | 40 | 07` (ignore): E-RABList SIZE(1..256), count-1 = 0 in one
/// aligned octet `00`; item IE 35 `00 23 | 40 | 02` (ignore), E-RABItem:
/// SEQUENCE ext 0, iE-Extensions absent 0, E-RAB-ID (0..15, ...) ext 0 and
/// `0101`, Cause CHOICE ext 0 and nas `010`, CauseNas ext 0 and detach `10`,
/// pad `00`: `0000 1010 | 0100 1000` = `0a 48`.
const RELEASE_COMMAND: &str = "0007001a0000030000000200010008000200010021400700002340020a48";

fn qos(qci: u8, gbr: bool) -> ErabLevelQosParameters {
    ErabLevelQosParameters {
        qci,
        arp: AllocationRetentionPriority {
            priority_level: 15,
            pre_emption_capability: true,
            pre_emption_vulnerability: false,
        },
        gbr_qos_info: gbr.then_some(GbrQosInformation {
            erab_max_bitrate_dl: 10_000_000_000,
            erab_max_bitrate_ul: 1,
            erab_guaranteed_bitrate_dl: 0,
            erab_guaranteed_bitrate_ul: 4_000_000,
        }),
    }
}

const IDS: [(u32, u32); 3] = [(0, 0), (1, 1), (0xFFFF_FFFF, 0xFF_FFFF)];

fn ambrs() -> [Option<UeAmbr>; 2] {
    [
        None,
        Some(UeAmbr {
            dl: 10_000_000_000,
            ul: 1,
        }),
    ]
}

#[test]
fn the_setup_request_round_trips_with_schema_criticalities() {
    let mut cases = 0;
    for (mme, enb) in IDS {
        for ue_ambr in ambrs() {
            for n in [1usize, 2, 8] {
                for gbr in [false, true] {
                    for addr in [vec![10, 0, 0, 1], (0u8..16).collect::<Vec<_>>()] {
                        for nas in [1usize, 300] {
                            let req = ErabSetupRequest {
                                mme_ue_s1ap_id: mme,
                                enb_ue_s1ap_id: enb,
                                ue_ambr,
                                erab_list: (0..n)
                                    .map(|i| ErabToBeSetupItem {
                                        erab_id: 5 + i as u8,
                                        erab_qos: qos(if gbr { 1 } else { 9 }, gbr),
                                        transport_layer_address: addr.clone(),
                                        gtp_teid: 0x1234_5678 + i as u32,
                                        nas_pdu: Some(vec![0x27; nas]),
                                    })
                                    .collect(),
                            };
                            let old = builder::build_erab_setup_request(&req).unwrap();
                            let new = build_erab_setup_request(&req).unwrap();
                            assert_eq!(hex(&new), hex(&old), "{req:?}");
                            cases += 1;
                        }
                    }
                }
            }
        }
    }
    assert_eq!(cases, 144);
}

#[test]
fn the_modify_request_round_trips_with_schema_criticalities() {
    let mut cases = 0;
    for (mme, enb) in IDS {
        for ue_ambr in ambrs() {
            for n in [1usize, 3] {
                for gbr in [false, true] {
                    let req = ErabModifyRequest {
                        mme_ue_s1ap_id: mme,
                        enb_ue_s1ap_id: enb,
                        ue_ambr,
                        erab_list: (0..n)
                            .map(|i| ErabToBeModifiedItem {
                                erab_id: 5 + i as u8,
                                erab_qos: qos(if gbr { 2 } else { 8 }, gbr),
                                nas_pdu: vec![0x62; 40],
                            })
                            .collect(),
                    };
                    let old = builder::build_erab_modify_request(&req).unwrap();
                    let new = build_erab_modify_request(&req).unwrap();
                    assert_eq!(hex(&new), hex(&old), "{req:?}");
                    cases += 1;
                }
            }
        }
    }
    assert_eq!(cases, 24);
}

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

#[test]
fn the_release_command_round_trips_with_schema_criticalities() {
    let mut cases = 0;
    for cause in causes() {
        for (mme, enb) in IDS {
            for ue_ambr in ambrs() {
                for nas_pdu in [None, Some(vec![0x27; 20])] {
                    for n in [1usize, 2] {
                        let cmd = ErabReleaseCommand {
                            mme_ue_s1ap_id: mme,
                            enb_ue_s1ap_id: enb,
                            ue_ambr,
                            erab_list: (0..n)
                                .map(|i| ErabItem {
                                    erab_id: 5 + i as u8,
                                    cause,
                                })
                                .collect(),
                            nas_pdu: nas_pdu.clone(),
                        };
                        let old = builder::build_erab_release_command(&cmd).unwrap();
                        let new = build_erab_release_command(&cmd).unwrap();
                        assert_eq!(hex(&new), hex(&old), "{cmd:?}");
                        cases += 1;
                    }
                }
            }
        }
    }
    assert!(cases > 1_000, "{cases}");
}

#[test]
fn the_release_command_is_the_x691_golden() {
    let cmd = ErabReleaseCommand {
        mme_ue_s1ap_id: 1,
        enb_ue_s1ap_id: 1,
        ue_ambr: None,
        erab_list: vec![ErabItem {
            erab_id: 5,
            cause: Cause::Nas(CauseNas::Detach),
        }],
        nas_pdu: None,
    };
    assert_eq!(
        hex(&build_erab_release_command(&cmd).unwrap()),
        RELEASE_COMMAND.replace(' ', "")
    );
}

fn setup_responses() -> Vec<ErabSetupResponse> {
    let mut out = Vec::new();
    for (mme, enb) in IDS {
        for setup in [0usize, 1, 3] {
            for failed in [0usize, 2] {
                if setup == 0 && failed == 0 {
                    continue;
                }
                out.push(ErabSetupResponse {
                    mme_ue_s1ap_id: mme,
                    enb_ue_s1ap_id: enb,
                    erab_setup_list: (0..setup)
                        .map(|i| ErabSetupItem {
                            erab_id: 5 + i as u8,
                            transport_layer_address: vec![192, 168, 0, i as u8],
                            gtp_teid: 0xDEAD_0000 + i as u32,
                        })
                        .collect(),
                    erab_failed_list: (0..failed)
                        .map(|i| ErabFailedItem {
                            erab_id: 10 + i as u8,
                            cause: causes()[i * 7],
                        })
                        .collect(),
                });
            }
        }
    }
    out
}

#[test]
fn the_setup_response_decodes_as_the_hand_written_parser_reads_it() {
    for rsp in setup_responses() {
        let bytes = builder::build_erab_setup_response(&rsp).unwrap();
        let S1apMessage::ErabSetupResponse(old) = decode_s1ap_pdu(&bytes).unwrap() else {
            panic!("oracle");
        };
        let ResponseDecode::Decoded { msg, notify } = decode_erab_setup_response(&bytes) else {
            panic!("{rsp:?}");
        };
        assert!(notify.is_empty());
        assert_eq!(format!("{msg:?}"), format!("{old:?}"));
    }
}

#[test]
fn the_modify_and_release_responses_decode_as_the_hand_written_parser_reads_them() {
    for (mme, enb) in IDS {
        for ok in [vec![], vec![5u8], vec![5, 6, 7]] {
            for failed in [0usize, 1] {
                if ok.is_empty() && failed == 0 {
                    continue;
                }
                let failed: Vec<_> = (0..failed)
                    .map(|i| ErabFailedItem {
                        erab_id: 9 + i as u8,
                        cause: causes()[3 + i],
                    })
                    .collect();
                let m = builder::build_erab_modify_response(&ErabModifyResponse {
                    mme_ue_s1ap_id: mme,
                    enb_ue_s1ap_id: enb,
                    erab_modify_list: ok.clone(),
                    erab_failed_list: failed.clone(),
                })
                .unwrap();
                let S1apMessage::ErabModifyResponse(old) = decode_s1ap_pdu(&m).unwrap() else {
                    panic!("oracle");
                };
                let ResponseDecode::Decoded { msg, .. } = decode_erab_modify_response(&m) else {
                    panic!("modify");
                };
                assert_eq!(format!("{msg:?}"), format!("{old:?}"));
                let r = builder::build_erab_release_response(&ErabReleaseResponse {
                    mme_ue_s1ap_id: mme,
                    enb_ue_s1ap_id: enb,
                    erab_release_list: ok.clone(),
                    erab_failed_list: failed,
                })
                .unwrap();
                let S1apMessage::ErabReleaseResponse(old) = decode_s1ap_pdu(&r).unwrap() else {
                    panic!("oracle");
                };
                let ResponseDecode::Decoded { msg, .. } = decode_erab_release_response(&r) else {
                    panic!("release");
                };
                assert_eq!(format!("{msg:?}"), format!("{old:?}"));
            }
        }
    }
}

/// Splice an unknown IE after the IE count of a message whose open-type length
/// is one octet.
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

fn small_setup_response() -> Vec<u8> {
    builder::build_erab_setup_response(&ErabSetupResponse {
        mme_ue_s1ap_id: 1,
        enb_ue_s1ap_id: 1,
        erab_setup_list: vec![ErabSetupItem {
            erab_id: 5,
            transport_layer_address: vec![10, 0, 0, 2],
            gtp_teid: 7,
        }],
        erab_failed_list: vec![],
    })
    .unwrap()
}

#[test]
fn unknown_ies_in_the_responses_are_handled_by_criticality() {
    let base = small_setup_response();
    assert!(matches!(
        decode_erab_setup_response(&splice(&base, 9999, IGNORE)),
        ResponseDecode::Decoded { notify, .. } if notify.is_empty()
    ));
    assert!(matches!(
        decode_erab_setup_response(&splice(&base, 9999, NOTIFY)),
        ResponseDecode::Decoded { notify, .. } if notify.len() == 1 && notify[0].id == 9999
    ));
    assert!(matches!(
        decode_erab_setup_response(&splice(&base, 9999, REJECT)),
        ResponseDecode::Failed(ies) if ies[0].id == 9999
    ));
    let release = builder::build_erab_release_response(&ErabReleaseResponse {
        mme_ue_s1ap_id: 1,
        enb_ue_s1ap_id: 1,
        erab_release_list: vec![5],
        erab_failed_list: vec![],
    })
    .unwrap();
    assert!(matches!(
        decode_erab_release_response(&splice(&release, 9999, REJECT)),
        ResponseDecode::Failed(_)
    ));
}

#[test]
fn through_the_handler_a_notify_ie_in_a_setup_response_is_reported() {
    let ctx = MmeContext::new();
    let enb = ctx.enb_add("127.0.0.1:36412".parse().unwrap());
    let out = handle_s1ap_message(&ctx, enb, &splice(&small_setup_response(), 9999, NOTIFY));
    let ei = out
        .iter()
        .find_map(|s| match decode_s1ap_pdu(&s.pdu).ok()? {
            S1apMessage::ErrorIndication(ei) => Some(ei),
            _ => None,
        })
        .expect("no Error Indication");
    let diag = ei.criticality_diagnostics.unwrap();
    assert_eq!(diag.procedure_code, Some(PROC_E_RAB_SETUP));
    assert_eq!(
        diag.triggering_message,
        Some(nextgcore_s1ap::triggering_message::SUCCESSFUL_OUTCOME)
    );
    assert_eq!(diag.ies[0].ie_id, 9999);
}

#[test]
fn through_the_handler_a_reject_ie_in_a_release_response_sends_nothing() {
    let ctx = MmeContext::new();
    let enb = ctx.enb_add("127.0.0.1:36412".parse().unwrap());
    let release = builder::build_erab_release_response(&ErabReleaseResponse {
        mme_ue_s1ap_id: 1,
        enb_ue_s1ap_id: 1,
        erab_release_list: vec![5],
        erab_failed_list: vec![],
    })
    .unwrap();
    assert!(handle_s1ap_message(&ctx, enb, &splice(&release, 9999, REJECT)).is_empty());
}

#[test]
fn the_production_builders_send_the_generated_bytes() {
    let ctx = MmeContext::new();
    let enb = ctx.enb_add("127.0.0.1:36412".parse().unwrap());
    let enb_ue_id = ctx.enb_ue_add(enb, 1);
    let enb_ue = ctx.enb_ue_find_by_id(enb_ue_id).unwrap();
    let bytes = crate::s1ap_build::build_e_rab_release_command(
        &enb_ue,
        5,
        S1apCauseGroup::Nas,
        crate::s1ap_build::nas_cause::DETACH,
        None,
    )
    .unwrap();
    let expected = build_erab_release_command(&ErabReleaseCommand {
        mme_ue_s1ap_id: enb_ue.mme_ue_s1ap_id,
        enb_ue_s1ap_id: 1,
        ue_ambr: None,
        erab_list: vec![ErabItem {
            erab_id: 5,
            cause: Cause::Nas(CauseNas::Detach),
        }],
        nas_pdu: None,
    })
    .unwrap();
    assert_eq!(hex(&bytes), hex(&expected));
}
