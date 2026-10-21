//! #514 stage 5: UE Context Release on the generated codec.
//!
//! Oracle: the pre-change hand-written builders and parser
//! (`nextgcore_s1ap_oracle::builder`, `decode_s1ap_pdu`). Golden: octets derived by
//! hand from X.691 (APER) for the TS 36.413 §9.1.4.5–§9.1.4.7 messages.

use super::*;
use crate::context::MmeContext;
use crate::context::S1apCauseGroup;
use crate::s1ap_build::cause_to_s1ap;
use crate::s1ap_handler::handle_s1ap_message;
use nextgcore_s1ap::{
    CauseNas, CauseRadioNetwork, S1apMessage, UeContextReleaseCommand, UeContextReleaseComplete,
    UeContextReleaseRequest, UeS1apIds,
};
use nextgcore_s1ap_oracle::{builder, decode_s1ap_pdu};

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// UE CONTEXT RELEASE COMMAND, UE-S1AP-ID-pair (1, 1), Cause nas / detach.
///
/// `00` initiatingMessage, `17` procedure 23, `00` criticality reject, `10`
/// open-type length 16. Value: `00` SEQUENCE ext bit + pad, `00 02` two IEs.
/// IE 99 (`00 63`, reject `00`, length `04`): CHOICE ext 0, index 0 (pair),
/// pair ext 0, iE-Extensions absent 0, MME-UE-S1AP-ID length-1 `00` -> `00`
/// then `01`; eNB-UE-S1AP-ID length-1 `00` + pad -> `00` then `01`. IE 2
/// (`00 02`, ignore `40`, length `01`): Cause CHOICE ext 0 + index 2 (nas)
/// `010`, CauseNas ext 0 + root index 2 of 4 `10`, pad -> `0010 0100` = `24`.
const COMMAND_PAIR: &str = "0017001000000200630004000100010002400124";
/// The same with UE-S1AP-IDs = mME-UE-S1AP-ID 1: CHOICE ext 0, index 1, MME
/// length-1 `00` + pad -> `40`, then `01`; open-type length 2, value length 14.
const COMMAND_MME_ONLY: &str = "0017000e0000020063000240010002400124";
/// UE CONTEXT RELEASE REQUEST (procedure 18, criticality ignore `40`), MME 1
/// (reject), eNB 1 (reject), Cause nas / normal-release (`0 010 0 00` + pad =
/// `20`).
const REQUEST: &str = "001240140000030000000200010008000200010002400120";
/// UE CONTEXT RELEASE COMPLETE (`20` successfulOutcome, procedure 23, reject),
/// MME 1 and eNB 1, both criticality ignore (`40`).
const COMPLETE: &str = "2017000f000002000040020001000840020001";

fn golden(s: &str) -> String {
    s.replace(' ', "")
}

fn unhex(s: &str) -> Vec<u8> {
    let s = golden(s);
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn the_command_is_the_x691_golden() {
    let pair = UeS1apIds::Pair {
        mme_ue_s1ap_id: 1,
        enb_ue_s1ap_id: 1,
    };
    let cause = Cause::Nas(CauseNas::Detach);
    assert_eq!(
        hex(&build_ue_context_release_command(&pair, cause).unwrap()),
        golden(COMMAND_PAIR)
    );
    let mme = UeS1apIds::MmeOnly { mme_ue_s1ap_id: 1 };
    assert_eq!(
        hex(&build_ue_context_release_command(&mme, cause).unwrap()),
        golden(COMMAND_MME_ONLY)
    );
}

#[test]
fn the_request_and_complete_goldens_decode() {
    let Class2Decode::Proceed { msg, notify } = decode_ue_context_release_request(&unhex(REQUEST))
    else {
        panic!("request did not decode");
    };
    assert!(notify.is_empty());
    assert_eq!((msg.mme_ue_s1ap_id, msg.enb_ue_s1ap_id), (1, 1));
    assert_eq!(msg.cause, Cause::Nas(CauseNas::NormalRelease));
    let ResponseDecode::Decoded { msg, notify } =
        decode_ue_context_release_complete(&unhex(COMPLETE))
    else {
        panic!("complete did not decode");
    };
    assert!(notify.is_empty());
    assert_eq!(
        msg,
        ReleaseComplete {
            mme_ue_s1ap_id: Some(1),
            enb_ue_s1ap_id: Some(1),
        }
    );
}

const IDS: [u32; 8] = [0, 1, 255, 256, 65_535, 65_536, 0xFF_FFFF, 0xFFFF_FFFF];
const ENB_IDS: [u32; 7] = [0, 1, 255, 256, 65_535, 65_536, 0xFF_FFFF];

/// Every cause mmed can send: each group, every value the hand-written
/// `cause_to_s1ap` maps (out-of-range ones fall back to the group default).
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
fn the_command_matches_the_hand_written_encoder() {
    let mut cases = 0;
    for cause in causes() {
        for &mme in &IDS {
            let mut ids = vec![UeS1apIds::MmeOnly {
                mme_ue_s1ap_id: mme,
            }];
            ids.extend(ENB_IDS.iter().map(|&enb| UeS1apIds::Pair {
                mme_ue_s1ap_id: mme,
                enb_ue_s1ap_id: enb,
            }));
            for ue_s1ap_ids in ids {
                let old = builder::build_ue_context_release_command(&UeContextReleaseCommand {
                    ue_s1ap_ids: ue_s1ap_ids.clone(),
                    cause,
                })
                .unwrap();
                let new = build_ue_context_release_command(&ue_s1ap_ids, cause).unwrap();
                assert_eq!(hex(&new), hex(&old), "{ue_s1ap_ids:?} {cause:?}");
                cases += 1;
            }
        }
    }
    assert!(cases > 2_000, "{cases}");
}

#[test]
fn the_request_decodes_as_the_hand_written_parser_reads_it() {
    let mut cases = 0;
    for cause in causes() {
        for &mme in &IDS {
            for &enb in &ENB_IDS {
                let req = UeContextReleaseRequest {
                    mme_ue_s1ap_id: mme,
                    enb_ue_s1ap_id: enb,
                    cause,
                };
                let bytes = builder::build_ue_context_release_request(&req).unwrap();
                let S1apMessage::UeContextReleaseRequest(old) = decode_s1ap_pdu(&bytes).unwrap()
                else {
                    panic!("oracle");
                };
                let Class2Decode::Proceed { msg, notify } =
                    decode_ue_context_release_request(&bytes)
                else {
                    panic!("{req:?}");
                };
                assert!(notify.is_empty());
                assert_eq!(format!("{msg:?}"), format!("{old:?}"));
                cases += 1;
            }
        }
    }
    assert!(cases > 2_000, "{cases}");
}

#[test]
fn the_complete_decodes_as_the_hand_written_parser_reads_it() {
    for &mme in &IDS {
        for &enb in &ENB_IDS {
            let bytes = builder::build_ue_context_release_complete(&UeContextReleaseComplete {
                mme_ue_s1ap_id: mme,
                enb_ue_s1ap_id: enb,
            })
            .unwrap();
            let S1apMessage::UeContextReleaseComplete(old) = decode_s1ap_pdu(&bytes).unwrap()
            else {
                panic!("oracle");
            };
            let ResponseDecode::Decoded { msg, .. } = decode_ue_context_release_complete(&bytes)
            else {
                panic!("{mme} {enb}");
            };
            assert_eq!(msg.mme_ue_s1ap_id, Some(old.mme_ue_s1ap_id));
            assert_eq!(msg.enb_ue_s1ap_id, Some(old.enb_ue_s1ap_id));
        }
    }
}

/// Splice an unknown IE after the IE count, with a one-octet open-type length.
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

/// Remove the IE with `id` (one-octet open-type length) from a message.
fn remove(msg: &[u8], id: u16) -> Vec<u8> {
    let body = &msg[4..];
    let count = u16::from_be_bytes([body[1], body[2]]);
    let mut ies = Vec::new();
    let mut at = 3;
    for _ in 0..count {
        let ie_id = u16::from_be_bytes([body[at], body[at + 1]]);
        let len = usize::from(body[at + 3]);
        let end = at + 4 + len;
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

#[test]
fn unknown_and_missing_ies_in_the_request_are_handled_by_criticality() {
    let base = unhex(REQUEST);
    assert!(matches!(
        decode_ue_context_release_request(&splice(&base, 9999, IGNORE)),
        Class2Decode::Proceed { notify, .. } if notify.is_empty()
    ));
    assert!(matches!(
        decode_ue_context_release_request(&splice(&base, 9999, NOTIFY)),
        Class2Decode::Proceed { notify, .. } if notify.len() == 1 && notify[0].id == 9999
    ));
    assert!(matches!(
        decode_ue_context_release_request(&splice(&base, 9999, REJECT)),
        Class2Decode::Reject { ies, mme_ue_s1ap_id: Some(1), enb_ue_s1ap_id: Some(1) }
            if ies[0].id == 9999
    ));
    // eNB-UE-S1AP-ID is reject: missing, the request is not run (§10.3.5).
    assert!(matches!(
        decode_ue_context_release_request(&remove(&base, ID_ENB_UE_S1AP_ID)),
        Class2Decode::Reject { ies, enb_ue_s1ap_id: None, .. }
            if ies[0].id == ID_ENB_UE_S1AP_ID
                && ies[0].type_of_error == g::TypeOfError::MISSING
    ));
    // Cause is ignore: missing, the request runs with radioNetwork / unspecified.
    let Class2Decode::Proceed { msg, .. } =
        decode_ue_context_release_request(&remove(&base, ID_CAUSE))
    else {
        panic!("a missing ignore IE must not stop the request");
    };
    assert_eq!(
        msg.cause,
        Cause::RadioNetwork(CauseRadioNetwork::Unspecified)
    );
}

#[test]
fn unknown_and_missing_ies_in_the_complete_are_handled_by_criticality() {
    let base = unhex(COMPLETE);
    assert!(matches!(
        decode_ue_context_release_complete(&splice(&base, 9999, NOTIFY)),
        ResponseDecode::Decoded { notify, .. } if notify.len() == 1
    ));
    assert!(matches!(
        decode_ue_context_release_complete(&splice(&base, 9999, REJECT)),
        ResponseDecode::Failed(ies) if ies[0].id == 9999
    ));
    // Both IDs are ignore: one missing still identifies the UE.
    assert!(matches!(
        decode_ue_context_release_complete(&remove(&base, ID_MME_UE_S1AP_ID)),
        ResponseDecode::Decoded { msg, .. }
            if msg == ReleaseComplete { mme_ue_s1ap_id: None, enb_ue_s1ap_id: Some(1) }
    ));
    assert!(matches!(
        decode_ue_context_release_complete(&remove(
            &remove(&base, ID_MME_UE_S1AP_ID),
            ID_ENB_UE_S1AP_ID
        )),
        ResponseDecode::Undecodable
    ));
}

/// An eNB with one UE; returns (enb pool id, enb_ue pool id, mme_ue_s1ap_id).
fn ue(ctx: &MmeContext) -> (u64, u64, u32) {
    let enb_id = ctx.enb_add("127.0.0.1:36412".parse().unwrap());
    let enb_ue_id = ctx.enb_ue_add(enb_id, 100);
    let mme_ue_id = ctx.mme_ue_add(enb_ue_id);
    ctx.enb_ue_associate_mme_ue(enb_ue_id, mme_ue_id);
    let mme_ue_s1ap_id = ctx.enb_ue_find_by_id(enb_ue_id).unwrap().mme_ue_s1ap_id;
    (enb_id, enb_ue_id, mme_ue_s1ap_id)
}

fn request_bytes(mme: u32) -> Vec<u8> {
    builder::build_ue_context_release_request(&UeContextReleaseRequest {
        mme_ue_s1ap_id: mme,
        enb_ue_s1ap_id: 100,
        cause: Cause::RadioNetwork(CauseRadioNetwork::UserInactivity),
    })
    .unwrap()
}

#[test]
fn through_the_handler_a_request_with_a_notify_ie_is_reported_and_still_answered() {
    let ctx = MmeContext::new();
    let (enb, _, mme) = ue(&ctx);
    let out = handle_s1ap_message(&ctx, enb, &splice(&request_bytes(mme), 9999, NOTIFY));
    let msgs: Vec<_> = out
        .iter()
        .map(|s| decode_s1ap_pdu(&s.pdu).unwrap())
        .collect();
    let ei = msgs
        .iter()
        .find_map(|m| match m {
            S1apMessage::ErrorIndication(ei) => Some(ei),
            _ => None,
        })
        .expect("no Error Indication");
    let diag = ei.criticality_diagnostics.as_ref().unwrap();
    assert_eq!(diag.procedure_code, Some(PROC_UE_CONTEXT_RELEASE_REQUEST));
    assert_eq!(diag.ies[0].ie_id, 9999);
    assert!(
        msgs.iter()
            .any(|m| matches!(m, S1apMessage::UeContextReleaseCommand(c)
                if c.cause == Cause::RadioNetwork(CauseRadioNetwork::UserInactivity))),
        "the request must still be answered with a Command"
    );
}

#[test]
fn through_the_handler_a_request_with_a_reject_ie_is_not_run() {
    let ctx = MmeContext::new();
    let (enb, _, mme) = ue(&ctx);
    let out = handle_s1ap_message(&ctx, enb, &splice(&request_bytes(mme), 9999, REJECT));
    assert_eq!(out.len(), 1);
    assert!(matches!(
        decode_s1ap_pdu(&out[0].pdu).unwrap(),
        S1apMessage::ErrorIndication(_)
    ));
}

#[test]
fn through_the_handler_a_complete_without_the_mme_id_releases_by_the_enb_id() {
    let ctx = MmeContext::new();
    let (enb, enb_ue_id, mme) = ue(&ctx);
    let complete = builder::build_ue_context_release_complete(&UeContextReleaseComplete {
        mme_ue_s1ap_id: mme,
        enb_ue_s1ap_id: 100,
    })
    .unwrap();
    let out = handle_s1ap_message(&ctx, enb, &remove(&complete, ID_MME_UE_S1AP_ID));
    assert!(out.is_empty());
    assert!(
        ctx.enb_ue_find_by_id(enb_ue_id).is_none(),
        "the UE named only by its eNB-UE-S1AP-ID must be released"
    );
}

#[test]
fn the_production_builder_sends_the_generated_command() {
    let bytes = crate::s1ap_build::build_ue_context_release_command(
        Some(1),
        1,
        S1apCauseGroup::Nas,
        crate::s1ap_build::nas_cause::DETACH,
    )
    .unwrap();
    assert_eq!(hex(&bytes), golden(COMMAND_PAIR));
}
