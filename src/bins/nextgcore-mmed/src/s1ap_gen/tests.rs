//! #514 stage 2: the S1 Setup family on the generated codec.
//!
//! The pre-change hand-written builders and parser are the oracle: the
//! generated encoders must produce the same bytes and the generated decoder the
//! same request. Golden octets come from nextgcore-s1ap's `golden_x691.rs`
//! (derived by hand from X.691 in #456).

use super::*;
use crate::context::{MmeContext, PlmnId, S1apCauseGroup, ServedGummei as CtxGummei};
use crate::s1ap_build::{
    self, hand_written_build_setup_failure, hand_written_build_setup_response,
};
use crate::s1ap_handler::handle_s1ap_message;
use nextgcore_s1ap::{builder, decode_s1ap_pdu, S1apMessage};

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

const PLMN: [u8; 3] = [0x99, 0xf9, 0x07];

/// nextgcore-s1ap `golden_x691.rs`: S1 Setup Response with MME name "mme", one
/// GUMMEI (PLMN 999-70, group 2, code 1), RelativeMMECapacity 255 (ignore).
const S1_SETUP_RESPONSE: &str =
    "20110020000003003d400501006d6d650069000b000099f90700000002000100574001ff";
/// nextgcore-s1ap `golden_x691.rs`: S1 Setup Failure, misc/unknown-PLMN, 10 s.
const S1_SETUP_FAILURE: &str = "4011000d00000200024001450041400130";
/// nextgcore-s1ap `golden_x691.rs`: nextgsim's eNB S1 Setup Request.
const S1_SETUP_REQUEST: &str = "00110031000004003b00080099f907000019b0003c400e05806e6578746773696d2d656e62004000070000004099f9070089400140";

fn ctx_with(name: Option<String>, gummeis: usize, capacity: u8) -> MmeContext {
    let mut ctx = MmeContext::new();
    ctx.mme_name = name;
    ctx.relative_capacity = capacity;
    ctx.served_gummei = (0..gummeis)
        .map(|i| CtxGummei {
            num_of_plmn_id: i + 1,
            plmn_id: (0..=i).map(|_| PlmnId::new("999", "70")).collect(),
            num_of_mme_gid: 2,
            mme_gid: vec![2, 0xFFFF],
            num_of_mme_code: 2,
            mme_code: vec![1, 0xFF],
        })
        .collect();
    ctx.num_of_served_gummei = gummeis;
    ctx
}

#[test]
fn the_setup_response_is_the_x691_golden() {
    let mut ctx = ctx_with(Some("mme".into()), 0, 255);
    ctx.served_gummei = vec![CtxGummei {
        num_of_plmn_id: 1,
        plmn_id: vec![PlmnId::new("999", "70")],
        num_of_mme_gid: 1,
        mme_gid: vec![2],
        num_of_mme_code: 1,
        mme_code: vec![1],
    }];
    assert_eq!(
        hex(&s1ap_build::build_setup_response(&ctx).unwrap()),
        S1_SETUP_RESPONSE
    );
}

#[test]
fn the_setup_failure_is_the_x691_golden() {
    let bytes = s1ap_build::build_setup_failure(
        S1apCauseGroup::Misc,
        s1ap_build::misc_cause::UNKNOWN_PLMN,
        Some(TimeToWait::V10s),
    )
    .unwrap();
    assert_eq!(hex(&bytes), S1_SETUP_FAILURE);
}

#[test]
fn the_setup_response_matches_the_hand_written_encoder() {
    let mut cases = 0;
    for name in [None, Some(1usize), Some(3), Some(40), Some(150)] {
        for gummeis in 1..=8usize {
            for capacity in [0u8, 1, 127, 255] {
                let ctx = ctx_with(name.map(|n| "m".repeat(n)), gummeis, capacity);
                assert_eq!(
                    s1ap_build::build_setup_response(&ctx).unwrap(),
                    hand_written_build_setup_response(&ctx).unwrap(),
                    "name {name:?}, {gummeis} GUMMEIs, capacity {capacity}"
                );
                cases += 1;
            }
        }
    }
    assert_eq!(cases, 160);
}

#[test]
fn the_setup_failure_matches_the_hand_written_encoder() {
    let groups = [
        S1apCauseGroup::Nothing,
        S1apCauseGroup::RadioNetwork,
        S1apCauseGroup::Transport,
        S1apCauseGroup::Nas,
        S1apCauseGroup::Protocol,
        S1apCauseGroup::Misc,
    ];
    let ttws = [
        None,
        Some(TimeToWait::V1s),
        Some(TimeToWait::V2s),
        Some(TimeToWait::V5s),
        Some(TimeToWait::V10s),
        Some(TimeToWait::V20s),
        Some(TimeToWait::V60s),
    ];
    let mut cases = 0;
    for group in groups {
        for value in -1i64..=60 {
            for ttw in ttws {
                assert_eq!(
                    s1ap_build::build_setup_failure(group, value, ttw).unwrap(),
                    hand_written_build_setup_failure(group, value, ttw).unwrap(),
                    "{group:?}/{value} {ttw:?}"
                );
                cases += 1;
            }
        }
    }
    assert_eq!(cases, 6 * 62 * 7);
}

fn requests() -> Vec<S1SetupRequest> {
    let mut out = Vec::new();
    for enb_id in [
        EnbId::Macro(0),
        EnbId::Macro(0x19B),
        EnbId::Macro(0xF_FFFF),
        EnbId::Home(0),
        EnbId::Home(0xFFF_FFFF),
    ] {
        for name in [None, Some("e".to_string()), Some("e".repeat(150))] {
            for tas in [1usize, 2, 256] {
                for drx in [
                    PagingDrx::V32,
                    PagingDrx::V64,
                    PagingDrx::V128,
                    PagingDrx::V256,
                ] {
                    out.push(S1SetupRequest {
                        global_enb_id: GlobalEnbId {
                            plmn_identity: PLMN,
                            enb_id,
                        },
                        enb_name: name.clone(),
                        supported_tas: (0..tas)
                            .map(|i| SupportedTaItem {
                                tac: u16::try_from(i).unwrap(),
                                broadcast_plmns: vec![PLMN; i % 6 + 1],
                            })
                            .collect(),
                        default_paging_drx: drx,
                    });
                }
            }
        }
    }
    out
}

fn same_request(a: &S1SetupRequest, b: &S1SetupRequest) -> bool {
    format!("{a:?}") == format!("{b:?}")
}

#[test]
fn the_request_decodes_as_the_hand_written_parser_reads_it() {
    let reqs = requests();
    assert_eq!(reqs.len(), 180);
    for req in &reqs {
        // Both encoders agree on the request, and both decoders read it back.
        let hand = builder::build_s1_setup_request(req).unwrap();
        assert_eq!(build_s1_setup_request(req).unwrap(), hand, "{req:?}");
        let SetupRequestDecode::Proceed { request, notify } = decode_s1_setup_request(&hand) else {
            panic!("generated decode refused {req:?}")
        };
        assert!(notify.is_empty());
        assert!(
            same_request(&request, req),
            "generated read {request:?} for {req:?}"
        );
        let S1apMessage::S1SetupRequest(old) = decode_s1ap_pdu(&hand).unwrap() else {
            panic!("hand-written parser misread {req:?}")
        };
        assert!(same_request(&old, &request));
    }
    // nextgsim's eNB request, the X.691 golden.
    let SetupRequestDecode::Proceed { request, .. } =
        decode_s1_setup_request(&unhex(S1_SETUP_REQUEST))
    else {
        panic!("golden refused")
    };
    assert_eq!(request.global_enb_id.enb_id, EnbId::Macro(0x19B));
    assert_eq!(request.enb_name.as_deref(), Some("nextgsim-enb"));
}

/// Insert one ProtocolIE-Field `id` / `criticality` / one-octet value right
/// after the IE count of an S1 SETUP REQUEST whose open type uses a one-octet
/// length (< 128), fixing up both the count and the length.
fn splice(request: &[u8], id: u16, criticality: u8, value: u8) -> Vec<u8> {
    assert_eq!(&request[..3], &[0x00, 0x11, 0x00]);
    let len = usize::from(request[3]);
    assert!(len < 0x7F, "test helper handles one-octet lengths only");
    let body = &request[4..];
    assert_eq!(body.len(), len);
    // body: ext 0 + pad (00) | count (2 octets) | IEs
    let count = u16::from_be_bytes([body[1], body[2]]) + 1;
    let ie = [(id >> 8) as u8, id as u8, criticality << 6, 0x01, value];
    let mut out = vec![
        0x00,
        0x11,
        0x00,
        u8::try_from(len + ie.len()).unwrap(),
        body[0],
    ];
    out.extend_from_slice(&count.to_be_bytes());
    out.extend_from_slice(&ie);
    out.extend_from_slice(&body[3..]);
    out
}

#[test]
fn unknown_ies_are_handled_by_criticality() {
    let base = unhex(S1_SETUP_REQUEST);
    // ignore: dropped, procedure proceeds, nothing reported.
    let SetupRequestDecode::Proceed { notify, .. } =
        decode_s1_setup_request(&splice(&base, 9999, IGNORE, 0))
    else {
        panic!("ignore refused")
    };
    assert!(notify.is_empty());
    // notify: proceeds and is reported.
    let SetupRequestDecode::Proceed { notify, .. } =
        decode_s1_setup_request(&splice(&base, 9999, NOTIFY, 0))
    else {
        panic!("notify refused")
    };
    assert_eq!(
        notify,
        vec![DiagnosedIe {
            criticality: NOTIFY,
            id: 9999,
            type_of_error: g::TypeOfError::NOT_UNDERSTOOD
        }]
    );
    // reject: the procedure is terminated.
    let SetupRequestDecode::Reject(ies) = decode_s1_setup_request(&splice(&base, 9999, REJECT, 0))
    else {
        panic!("reject proceeded")
    };
    assert_eq!(
        ies,
        vec![DiagnosedIe {
            criticality: REJECT,
            id: 9999,
            type_of_error: g::TypeOfError::NOT_UNDERSTOOD
        }]
    );
}

#[test]
fn a_missing_mandatory_ie_is_reported_as_missing() {
    // The request without its Global-ENB-ID (criticality reject, §10.3.5).
    let mut req = requests().remove(0);
    req.enb_name = None;
    let full = build_s1_setup_request(&req).unwrap();
    let pdu = nextgcore_s1ap_gen::decode(&full).unwrap();
    let g::S1AP_PDU::InitiatingMessage(mut msg) = pdu else {
        panic!()
    };
    let g::InitiatingMessageValue::Id_S1Setup(ref mut v) = msg.value else {
        panic!()
    };
    v.protocol_i_es.0.retain(|ie| ie.id.0 != ID_GLOBAL_ENB_ID);
    let bytes = nextgcore_s1ap_gen::encode(&g::S1AP_PDU::InitiatingMessage(msg)).unwrap();
    let SetupRequestDecode::Reject(ies) = decode_s1_setup_request(&bytes) else {
        panic!("a request without Global-ENB-ID proceeded")
    };
    assert_eq!(
        ies,
        vec![DiagnosedIe {
            criticality: REJECT,
            id: ID_GLOBAL_ENB_ID,
            type_of_error: g::TypeOfError::MISSING
        }]
    );
}

fn served_ctx() -> MmeContext {
    let mut ctx = ctx_with(Some("mme".into()), 1, 255);
    assert!(crate::config::load_config(
        &mut ctx,
        "../../../docker/rust/configs/epc/mme.yaml"
    ));
    ctx
}

fn shipped_request() -> S1SetupRequest {
    let plmn = s1ap_build::encode_plmn_id(&PlmnId::new("999", "70"));
    S1SetupRequest {
        global_enb_id: GlobalEnbId {
            plmn_identity: plmn,
            enb_id: EnbId::Macro(0x1234),
        },
        enb_name: Some("enb".into()),
        supported_tas: vec![SupportedTaItem {
            tac: 1,
            broadcast_plmns: vec![plmn],
        }],
        default_paging_drx: PagingDrx::V128,
    }
}

#[test]
fn a_reject_ie_through_the_handler_gets_s1_setup_failure_with_diagnostics() {
    let ctx = served_ctx();
    let enb = ctx.enb_add("127.0.0.1:36412".parse().unwrap());
    let request = splice(
        &build_s1_setup_request(&shipped_request()).unwrap(),
        9999,
        REJECT,
        0,
    );
    let out = handle_s1ap_message(&ctx, enb, &request);
    assert_eq!(out.len(), 1);
    let pdu = nextgcore_s1ap_gen::decode(&out[0].pdu).unwrap();
    let g::S1AP_PDU::UnsuccessfulOutcome(f) = pdu else {
        panic!("not a failure: {pdu:?}")
    };
    let g::UnsuccessfulOutcomeValue::Id_S1Setup(f) = f.value else {
        panic!()
    };
    let mut saw_cause = false;
    let mut saw_diag = false;
    for ie in f.protocol_i_es.0 {
        match ie.value {
            g::S1SetupFailureProtocolIEs_EntryValue::Id_Cause(g::Cause::Protocol(p)) => {
                assert_eq!(p.0, g::CauseProtocol::ABSTRACT_SYNTAX_ERROR_REJECT);
                saw_cause = true;
            }
            g::S1SetupFailureProtocolIEs_EntryValue::Id_CriticalityDiagnostics(d) => {
                assert_eq!(d.procedure_code, Some(g::ProcedureCode(PROC_S1_SETUP)));
                let ies = d.i_es_criticality_diagnostics.unwrap().0;
                assert_eq!(ies.len(), 1);
                assert_eq!(ies[0].ie_id.0, 9999);
                saw_diag = true;
            }
            _ => {}
        }
    }
    assert!(saw_cause && saw_diag);
    assert!(!ctx.enb_find_by_id(enb).unwrap().state.s1_setup_success);
}

#[test]
fn a_notify_ie_through_the_handler_is_reported_in_the_response() {
    let ctx = served_ctx();
    let enb = ctx.enb_add("127.0.0.1:36412".parse().unwrap());
    let request = splice(
        &build_s1_setup_request(&shipped_request()).unwrap(),
        9999,
        NOTIFY,
        0,
    );
    let out = handle_s1ap_message(&ctx, enb, &request);
    assert_eq!(out.len(), 1);
    let pdu = nextgcore_s1ap_gen::decode(&out[0].pdu).unwrap();
    let g::S1AP_PDU::SuccessfulOutcome(r) = pdu else {
        panic!("not a response: {pdu:?}")
    };
    let g::SuccessfulOutcomeValue::Id_S1Setup(r) = r.value else {
        panic!()
    };
    let diag = r.protocol_i_es.0.into_iter().find_map(|ie| match ie.value {
        g::S1SetupResponseProtocolIEs_EntryValue::Id_CriticalityDiagnostics(d) => Some(d),
        _ => None,
    });
    let ies = diag
        .expect("no diagnostics")
        .i_es_criticality_diagnostics
        .unwrap()
        .0;
    assert_eq!((ies[0].ie_id.0, ies[0].ie_criticality.0), (9999, NOTIFY));
    assert!(ctx.enb_find_by_id(enb).unwrap().state.s1_setup_success);
}

#[test]
fn an_ignore_ie_through_the_handler_sets_up_as_before() {
    let ctx = served_ctx();
    let enb = ctx.enb_add("127.0.0.1:36412".parse().unwrap());
    let plain = build_s1_setup_request(&shipped_request()).unwrap();
    let out_plain = handle_s1ap_message(&ctx, enb, &plain);
    let enb2 = ctx.enb_add("127.0.0.2:36412".parse().unwrap());
    let out_ignore = handle_s1ap_message(&ctx, enb2, &splice(&plain, 9999, IGNORE, 0));
    assert_eq!(out_plain[0].pdu, out_ignore[0].pdu);
    assert!(ctx.enb_find_by_id(enb2).unwrap().state.s1_setup_success);
}
