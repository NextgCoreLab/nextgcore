//! #514 stage 12: the rest of mmed's S1AP on the generated codec.
//!
//! Oracle: the pre-change hand-written builders and parser
//! (`test_codec::builder`, `decode_s1ap_pdu`: since #514 stage 13b the generated codec with an independently written domain mapping, and builders for messages mmed sends check that their output decodes back to their input). Golden: octets derived by
//! hand from X.691 (APER) for TS 36.413 §9.1.8.14.

use super::*;
use crate::context::{MmeContext, S1apCauseGroup};
use crate::s1ap_build::cause_to_s1ap;
use crate::s1ap_gen::test_codec::{builder, decode_s1ap_pdu};
use crate::s1ap_handler::handle_s1ap_message;
use nextgcore_s1ap::{
    CsFallbackIndicator, EnbConfigurationUpdate, EnbConfigurationUpdateAcknowledge,
    EnbConfigurationUpdateFailure, KillRequest, MmeConfigurationUpdateAcknowledge,
    MmeConfigurationUpdateFailure, NasNonDeliveryIndication, OverloadAction, OverloadStart,
    OverloadStop, ResetAcknowledge, S1apMessage, UeAssociatedLogicalS1Connection,
    UeCapabilityInfoIndication, UeContextModificationFailure, UeContextModificationRequest,
    UeContextModificationResponse, UeSecurityCapabilities, WarningAreaList,
    WriteReplaceWarningRequest,
};

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// OVERLOAD STOP: `00 23 00 03` (initiating message: ext 0, index 00, pad;
/// procedure 35; reject; length 3), then the value `00 00 00` (ext 0 + pad, an
/// empty IE container: count 0 in two octets).
const OVERLOAD_STOP: &str = "00230003000000";

#[test]
fn the_overload_stop_is_the_x691_golden() {
    assert_eq!(hex(&build_overload_stop().unwrap()), OVERLOAD_STOP);
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

const TTWS: [Option<TimeToWait>; 7] = [
    None,
    Some(TimeToWait::V1s),
    Some(TimeToWait::V2s),
    Some(TimeToWait::V5s),
    Some(TimeToWait::V10s),
    Some(TimeToWait::V20s),
    Some(TimeToWait::V60s),
];

const ACTIONS: [OverloadAction; 7] = [
    OverloadAction::RejectNonEmergencyMoDt,
    OverloadAction::RejectRrcCrSignalling,
    OverloadAction::PermitEmergencySessionsAndMtOnly,
    OverloadAction::PermitHighPrioritySessionsAndMtOnly,
    OverloadAction::RejectDelayTolerantAccess,
    OverloadAction::PermitHighPrioritySessionsAndExceptionReportingAndMtOnly,
    OverloadAction::NotAcceptMoDataOrDelayTolerantAccessFromCpCiot,
];

#[test]
fn the_configuration_update_answers_and_overload_match_the_hand_written_encoder() {
    assert_eq!(
        hex(&build_enb_configuration_update_acknowledge(&[]).unwrap()),
        hex(&builder::build_enb_configuration_update_acknowledge(
            &EnbConfigurationUpdateAcknowledge {
                criticality_diagnostics: None
            }
        )
        .unwrap())
    );
    let mut cases = 0;
    for cause in causes() {
        for ttw in TTWS {
            assert_eq!(
                hex(&build_enb_configuration_update_failure(cause, ttw, &[]).unwrap()),
                hex(&builder::build_enb_configuration_update_failure(
                    &EnbConfigurationUpdateFailure {
                        cause,
                        time_to_wait: ttw,
                        criticality_diagnostics: None,
                    }
                )
                .unwrap()),
                "{cause:?} {ttw:?}"
            );
            cases += 1;
        }
    }
    for action in ACTIONS {
        assert_eq!(
            hex(&build_overload_start(action).unwrap()),
            hex(&builder::build_overload_start(&OverloadStart {
                overload_action: action
            })
            .unwrap()),
            "{action:?}"
        );
    }
    assert_eq!(
        hex(&build_overload_stop().unwrap()),
        hex(&builder::build_overload_stop(&OverloadStop).unwrap())
    );
    assert!(cases > 300, "{cases}");
}

#[test]
fn the_ue_context_modification_request_matches_the_hand_written_encoder() {
    let mut cases = 0;
    for (mme, enb) in [(0, 0), (1, 1), (0xFFFF_FFFF, 0xFF_FFFF)] {
        for mask in 0u8..32 {
            let req = UeContextModificationRequest {
                mme_ue_s1ap_id: mme,
                enb_ue_s1ap_id: enb,
                security_key: (mask & 1 != 0).then_some([0x5A; 32]),
                subscriber_profile_id_for_rfp: (mask & 2 != 0).then_some(256),
                ue_ambr: (mask & 4 != 0).then_some(nextgcore_s1ap::UeAmbr {
                    dl: 10_000_000_000,
                    ul: 1,
                }),
                cs_fallback_indicator: (mask & 8 != 0).then_some(if mask & 16 != 0 {
                    CsFallbackIndicator::CsFallbackHighPriority
                } else {
                    CsFallbackIndicator::CsFallbackRequired
                }),
                ue_security_capabilities: (mask & 16 != 0).then_some(UeSecurityCapabilities {
                    encryption_algorithms: 0xE000,
                    integrity_algorithms: 0x6000,
                }),
            };
            assert_eq!(
                hex(&build_ue_context_modification_request(&req).unwrap()),
                hex(&builder::build_ue_context_modification_request(&req).unwrap()),
                "{req:?}"
            );
            cases += 1;
        }
    }
    assert_eq!(cases, 96);
}

fn areas() -> Vec<Option<WarningAreaList>> {
    let plmn = [0x13, 0x00, 0x14];
    vec![
        None,
        Some(WarningAreaList::CellIdList(vec![
            EutranCgi {
                plmn_identity: plmn,
                cell_identity: 0x0FFF_FFFF,
            },
            EutranCgi {
                plmn_identity: plmn,
                cell_identity: 1,
            },
        ])),
        Some(WarningAreaList::TrackingAreaListForWarning(vec![Tai {
            plmn_identity: plmn,
            tac: 0xFFFF,
        }])),
        Some(WarningAreaList::EmergencyAreaIdList(vec![
            [1, 2, 3],
            [4, 5, 6],
        ])),
    ]
}

#[test]
fn the_pws_requests_match_the_hand_written_encoder() {
    let mut cases = 0;
    for area in areas() {
        for mask in 0u8..32 {
            let req = WriteReplaceWarningRequest {
                message_identifier: 0x1112,
                serial_number: 0x3FF0,
                warning_area: area.clone(),
                repetition_period: if mask & 1 != 0 { 4095 } else { 0 },
                number_of_broadcast_request: if mask & 2 != 0 { 65535 } else { 1 },
                warning_type: (mask & 4 != 0).then_some([0x01, 0x80]),
                warning_security_info: (mask & 8 != 0).then_some([0xA5; 50]),
                data_coding_scheme: (mask & 16 != 0).then_some(0x0F),
                warning_message_contents: (mask & 1 != 0).then(|| (0..120u8).collect()),
                concurrent_warning_message_indicator: mask & 2 != 0,
            };
            assert_eq!(
                hex(&build_write_replace_warning_request(&req).unwrap()),
                hex(&builder::build_write_replace_warning_request(&req).unwrap()),
                "{req:?}"
            );
            cases += 1;
        }
        for kill_all in [false, true] {
            let req = KillRequest {
                message_identifier: 0x1112,
                serial_number: 0x3FF0,
                warning_area: area.clone(),
                kill_all_warning_messages: kill_all,
            };
            assert_eq!(
                hex(&build_kill_request(&req).unwrap()),
                hex(&builder::build_kill_request(&req).unwrap()),
                "{req:?}"
            );
            cases += 1;
        }
    }
    assert_eq!(cases, 4 * 34);
}

fn same<A: std::fmt::Debug, B: std::fmt::Debug>(a: &A, b: &B) -> bool {
    format!("{a:?}") == format!("{b:?}")
}

#[test]
fn the_decodes_read_as_the_hand_written_parser_reads_them() {
    let mut cases = 0;
    // ENB CONFIGURATION UPDATE: every optional-IE combination.
    for mask in 0u8..8 {
        let upd = EnbConfigurationUpdate {
            enb_name: (mask & 1 != 0).then(|| "enb-1".to_string()),
            supported_tas: (mask & 2 != 0).then(|| {
                vec![SupportedTaItem {
                    tac: 7,
                    broadcast_plmns: vec![[0x13, 0x00, 0x14], [0x00, 0xF1, 0x10]],
                }]
            }),
            default_paging_drx: (mask & 4 != 0).then_some(PagingDrx::V256),
        };
        let bytes = builder::build_enb_configuration_update(&upd).unwrap();
        let Ok(S1apMessage::EnbConfigurationUpdate(old)) = decode_s1ap_pdu(&bytes) else {
            panic!("oracle");
        };
        let ConfigUpdateDecode::Proceed { msg, notify } = decode_enb_configuration_update(&bytes)
        else {
            panic!("{old:?}");
        };
        assert!(notify.is_empty() && same(&msg, &old), "{msg:?} vs {old:?}");
        cases += 1;
    }
    for cause in causes() {
        let nnd = NasNonDeliveryIndication {
            mme_ue_s1ap_id: 0xFFFF_FFFF,
            enb_ue_s1ap_id: 0xFF_FFFF,
            nas_pdu: vec![0x07, 0x41, 0x71],
            cause,
        };
        let bytes = builder::build_nas_non_delivery_indication(&nnd).unwrap();
        let Ok(S1apMessage::NasNonDeliveryIndication(old)) = decode_s1ap_pdu(&bytes) else {
            panic!("oracle");
        };
        let Class2Decode::Proceed { msg, .. } = decode_nas_non_delivery_indication(&bytes) else {
            panic!("{old:?}");
        };
        assert!(same(&msg, &old));
        let f = UeContextModificationFailure {
            mme_ue_s1ap_id: 1,
            enb_ue_s1ap_id: 2,
            cause,
            criticality_diagnostics: None,
        };
        let bytes = builder::build_ue_context_modification_failure(&f).unwrap();
        let Ok(S1apMessage::UeContextModificationFailure(old)) = decode_s1ap_pdu(&bytes) else {
            panic!("oracle");
        };
        let ResponseDecode::Decoded { msg, .. } = decode_ue_context_modification_failure(&bytes)
        else {
            panic!("{old:?}");
        };
        assert!(same(&msg, &old));
        for ttw in TTWS {
            let f = MmeConfigurationUpdateFailure {
                cause,
                time_to_wait: ttw,
                criticality_diagnostics: None,
            };
            let bytes = builder::build_mme_configuration_update_failure(&f).unwrap();
            let Ok(S1apMessage::MmeConfigurationUpdateFailure(old)) = decode_s1ap_pdu(&bytes)
            else {
                panic!("oracle");
            };
            let ResponseDecode::Decoded { msg, .. } =
                decode_mme_configuration_update_failure(&bytes)
            else {
                panic!("{old:?}");
            };
            assert!(same(&msg, &old));
            cases += 1;
        }
        cases += 2;
    }
    for len in [1usize, 127, 128, 3000] {
        let ind = UeCapabilityInfoIndication {
            mme_ue_s1ap_id: 0xFFFF_FFFF,
            enb_ue_s1ap_id: 0,
            ue_radio_capability: (0..len).map(|i| i as u8).collect(),
        };
        let bytes = builder::build_ue_capability_info_indication(&ind).unwrap();
        let Ok(S1apMessage::UeCapabilityInfoIndication(old)) = decode_s1ap_pdu(&bytes) else {
            panic!("oracle");
        };
        let Class2Decode::Proceed { msg, .. } = decode_ue_capability_info_indication(&bytes) else {
            panic!("{old:?}");
        };
        assert!(same(&msg, &old));
        cases += 1;
    }
    for n in [0usize, 1, 3] {
        let ack = ResetAcknowledge {
            ue_associated_connections: (0..n)
                .map(|i| UeAssociatedLogicalS1Connection {
                    mme_ue_s1ap_id: (i != 1).then_some(i as u32),
                    enb_ue_s1ap_id: (i != 2).then_some(0xFF_FFFF - i as u32),
                })
                .collect(),
        };
        let bytes = builder::build_reset_acknowledge(&ack).unwrap();
        let Ok(S1apMessage::ResetAcknowledge(old)) = decode_s1ap_pdu(&bytes) else {
            panic!("oracle");
        };
        let ResponseDecode::Decoded { msg, .. } = decode_reset_acknowledge(&bytes) else {
            panic!("{old:?}");
        };
        assert!(same(&msg, &old));
        cases += 1;
    }
    let bytes = builder::build_ue_context_modification_response(&UeContextModificationResponse {
        mme_ue_s1ap_id: 0xFFFF_FFFF,
        enb_ue_s1ap_id: 0xFF_FFFF,
        criticality_diagnostics: None,
    })
    .unwrap();
    let Ok(S1apMessage::UeContextModificationResponse(old)) = decode_s1ap_pdu(&bytes) else {
        panic!("oracle");
    };
    let ResponseDecode::Decoded { msg, .. } = decode_ue_context_modification_response(&bytes)
    else {
        panic!("{old:?}");
    };
    assert!(same(&msg, &old));
    let bytes =
        builder::build_mme_configuration_update_acknowledge(&MmeConfigurationUpdateAcknowledge {
            criticality_diagnostics: None,
        })
        .unwrap();
    assert!(matches!(
        decode_mme_configuration_update_acknowledge(&bytes),
        ResponseDecode::Decoded { .. }
    ));
    assert!(cases > 400, "{cases}");
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

fn update() -> Vec<u8> {
    builder::build_enb_configuration_update(&EnbConfigurationUpdate {
        enb_name: Some("enb".into()),
        supported_tas: None,
        default_paging_drx: None,
    })
    .unwrap()
}

fn set_up_enb(ctx: &MmeContext) -> u64 {
    let enb = ctx.enb_add("127.0.0.1:36412".parse().unwrap());
    if let Some(e) = ctx.enb_pool.write().unwrap().get_mut(&enb) {
        e.state.s1_setup_success = true;
    }
    enb
}

#[test]
fn through_the_handler_a_notify_ie_in_a_configuration_update_reaches_the_acknowledge() {
    let ctx = MmeContext::new();
    let enb = set_up_enb(&ctx);
    let out = handle_s1ap_message(&ctx, enb, &splice(&update(), 9999, NOTIFY));
    assert_eq!(out.len(), 1);
    let Ok(g::S1AP_PDU::SuccessfulOutcome(g::SuccessfulOutcome {
        value: g::SuccessfulOutcomeValue::Id_ENBConfigurationUpdate(ack),
        ..
    })) = nextgcore_s1ap_gen::decode(&out[0].pdu)
    else {
        panic!("expected an acknowledge");
    };
    let Some(
        g::ENBConfigurationUpdateAcknowledgeProtocolIEs_EntryValue::Id_CriticalityDiagnostics(d),
    ) = ack.protocol_i_es.0.first().map(|ie| ie.value.clone())
    else {
        panic!("the acknowledge must carry Criticality Diagnostics");
    };
    assert_eq!(
        d.i_es_criticality_diagnostics.unwrap().0[0].ie_id,
        g::ProtocolIE_ID(9999)
    );
}

#[test]
fn through_the_handler_a_reject_ie_in_a_configuration_update_gets_the_failure() {
    let ctx = MmeContext::new();
    let enb = set_up_enb(&ctx);
    let out = handle_s1ap_message(&ctx, enb, &splice(&update(), 9999, REJECT));
    assert_eq!(out.len(), 1);
    let Ok(S1apMessage::EnbConfigurationUpdateFailure(f)) = decode_s1ap_pdu(&out[0].pdu) else {
        panic!("expected a failure");
    };
    assert_eq!(
        f.cause,
        cause_to_s1ap(
            S1apCauseGroup::Protocol,
            crate::s1ap_build::protocol_cause::ABSTRACT_SYNTAX_ERROR_REJECT
        )
    );
}

#[test]
fn class2_and_response_ies_are_handled_by_criticality() {
    let nnd = builder::build_nas_non_delivery_indication(&NasNonDeliveryIndication {
        mme_ue_s1ap_id: 1,
        enb_ue_s1ap_id: 1,
        nas_pdu: vec![0x07],
        cause: Cause::Nas(nextgcore_s1ap::CauseNas::Unspecified),
    })
    .unwrap();
    assert!(matches!(
        decode_nas_non_delivery_indication(&remove(&nnd, ID_MME_UE_S1AP_ID)),
        Class2Decode::Reject { ies, .. } if ies[0].id == ID_MME_UE_S1AP_ID
    ));
    // NAS-PDU and Cause are `ignore`: missing, the indication still proceeds.
    assert!(matches!(
        decode_nas_non_delivery_indication(&remove(&nnd, ID_CAUSE)),
        Class2Decode::Proceed { .. }
    ));
    let ctx = MmeContext::new();
    let enb = set_up_enb(&ctx);
    // A reject IE in a NAS Non Delivery Indication: ERROR INDICATION, nothing else.
    let out = handle_s1ap_message(&ctx, enb, &splice(&nnd, 9999, REJECT));
    assert_eq!(out.len(), 1);
    assert!(matches!(
        decode_s1ap_pdu(&out[0].pdu),
        Ok(S1apMessage::ErrorIndication(_))
    ));
    let f = builder::build_ue_context_modification_failure(&UeContextModificationFailure {
        mme_ue_s1ap_id: 1,
        enb_ue_s1ap_id: 1,
        cause: Cause::Nas(nextgcore_s1ap::CauseNas::Unspecified),
        criticality_diagnostics: None,
    })
    .unwrap();
    // A reject IE in a response is handled locally: nothing is sent.
    assert!(handle_s1ap_message(&ctx, enb, &splice(&f, 9999, REJECT)).is_empty());
    // ... a notify IE is reported by ERROR INDICATION.
    let out = handle_s1ap_message(&ctx, enb, &splice(&f, 9999, NOTIFY));
    assert!(out
        .iter()
        .any(|s| matches!(decode_s1ap_pdu(&s.pdu), Ok(S1apMessage::ErrorIndication(_)))));
}

#[test]
fn the_pws_responses_decode_as_the_hand_written_parser_reads_them() {
    use nextgcore_s1ap::{
        BroadcastCancelledAreaList as C, BroadcastCompletedAreaList as B, CellIdCancelledItem,
        EmergencyAreaIdBroadcastItem, EmergencyAreaIdCancelledItem, KillResponse, TaiBroadcastItem,
        TaiCancelledItem, WriteReplaceWarningResponse,
    };
    let cell = |c: u32| EutranCgi {
        plmn_identity: [0x13, 0x00, 0x14],
        cell_identity: c,
    };
    let tai = Tai {
        plmn_identity: [0x13, 0x00, 0x14],
        tac: 9,
    };
    let completed = [
        None,
        Some(B::CellIdBroadcast(vec![cell(1), cell(0x0FFF_FFFF)])),
        Some(B::TaiBroadcast(vec![TaiBroadcastItem {
            tai: tai.clone(),
            completed_cells: vec![cell(2)],
        }])),
        Some(B::EmergencyAreaIdBroadcast(vec![
            EmergencyAreaIdBroadcastItem {
                emergency_area_id: [1, 2, 3],
                completed_cells: vec![cell(3), cell(4)],
            },
        ])),
    ];
    let cc = |c: u32, n: u16| CellIdCancelledItem {
        ecgi: cell(c),
        number_of_broadcasts: n,
    };
    let cancelled = [
        None,
        Some(C::CellIdCancelled(vec![cc(1, 0), cc(2, 65535)])),
        Some(C::TaiCancelled(vec![TaiCancelledItem {
            tai: tai.clone(),
            cancelled_cells: vec![cc(5, 7)],
        }])),
        Some(C::EmergencyAreaIdCancelled(vec![
            EmergencyAreaIdCancelledItem {
                emergency_area_id: [9, 9, 9],
                cancelled_cells: vec![cc(6, 1)],
            },
        ])),
    ];
    for area in completed {
        let r = WriteReplaceWarningResponse {
            message_identifier: 0x1112,
            serial_number: 0xFFFF,
            broadcast_completed_area: area,
            criticality_diagnostics: None,
        };
        let bytes = builder::build_write_replace_warning_response(&r).unwrap();
        let Ok(S1apMessage::WriteReplaceWarningResponse(old)) = decode_s1ap_pdu(&bytes) else {
            panic!("oracle");
        };
        let ResponseDecode::Decoded { msg, .. } = decode_write_replace_warning_response(&bytes)
        else {
            panic!("{old:?}");
        };
        assert!(same(&msg, &old), "{msg:?} vs {old:?}");
    }
    for area in cancelled {
        let r = KillResponse {
            message_identifier: 0,
            serial_number: 0x8001,
            broadcast_cancelled_area: area,
            criticality_diagnostics: None,
        };
        let bytes = builder::build_kill_response(&r).unwrap();
        let Ok(S1apMessage::KillResponse(old)) = decode_s1ap_pdu(&bytes) else {
            panic!("oracle");
        };
        let ResponseDecode::Decoded { msg, .. } = decode_kill_response(&bytes) else {
            panic!("{old:?}");
        };
        assert!(same(&msg, &old), "{msg:?} vs {old:?}");
        // Serial Number is `reject`: missing, the response is handled locally.
        assert!(matches!(
            decode_kill_response(&remove(&bytes, ID_SERIAL_NUMBER)),
            ResponseDecode::Failed(ies) if ies[0].id == ID_SERIAL_NUMBER
        ));
    }
}
