//! #514 stage 9: Reset and Error Indication on the generated codec.
//!
//! Oracle: the pre-change hand-written builders and parser
//! (`nextgcore_s1ap::builder`, `decode_s1ap_pdu`). Golden: octets derived by
//! hand from X.691 (APER) for TS 36.413 §9.1.8.1, §9.1.8.2 and §9.1.8.4.

use super::*;
use crate::context::{MmeContext, S1apCauseGroup};
use crate::s1ap_build::cause_to_s1ap;
use crate::s1ap_handler::handle_s1ap_message;
use nextgcore_s1ap::{
    builder, decode_s1ap_pdu, CauseNas, CriticalityDiagnostics, ErrorIndication,
    IeCriticalityDiagnostics, Reset, ResetAcknowledge, ResetType, S1apMessage, TypeOfError,
    UeAssociatedLogicalS1Connection,
};

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// ERROR INDICATION, MME 1 / eNB 1, Cause nas / detach: `00 0f 40 14`
/// (procedure 15, criticality ignore, length 20), `00 00 03`, the two IDs at
/// ignore (`40`, length 2, `00 01`), Cause IE 2 at ignore, `0 010 0 10` and
/// pad = `24`.
const ERROR_INDICATION: &str = "000f40140000030000400200010008400200010002400124";
/// RESET ACKNOWLEDGE with no IEs: `20 0e 00 03` (successful outcome,
/// procedure 14, reject, length 3), value `00 00 00` (ext bit + pad, zero
/// IEs).
const RESET_ACK_EMPTY: &str = "200e0003000000";
/// RESET, Cause nas / detach, ResetType s1-Interface (reset-all):
/// `00 0e 00 0d`, `00 00 02`; Cause `00 02 40 01 24`; ResetType IE 92
/// `00 5c 00 01` (reject): CHOICE ext 0, index 0, ResetAll ENUMERATED with
/// one root value (ext 0, no index bits), pad = `00`.
const RESET_ALL: &str = "000e000d0000020002400124005c000100";

#[test]
fn the_goldens() {
    let ei = build_error_indication(&ErrorIndication {
        mme_ue_s1ap_id: Some(1),
        enb_ue_s1ap_id: Some(1),
        cause: Some(Cause::Nas(CauseNas::Detach)),
        criticality_diagnostics: None,
    })
    .unwrap();
    assert_eq!(hex(&ei), ERROR_INDICATION);
    let ack = build_reset_acknowledge(
        &ResetAcknowledge {
            ue_associated_connections: vec![],
        },
        &[],
    )
    .unwrap();
    assert_eq!(hex(&ack), RESET_ACK_EMPTY);
    let Class2Decode::Proceed { msg, notify } = decode_reset(&unhex(RESET_ALL)) else {
        panic!("the golden RESET must decode");
    };
    assert!(notify.is_empty());
    assert_eq!(msg.cause, Cause::Nas(CauseNas::Detach));
    assert!(matches!(msg.reset_type, ResetType::S1Interface));
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

fn diagnostics() -> [Option<CriticalityDiagnostics>; 3] {
    [
        None,
        Some(CriticalityDiagnostics {
            procedure_code: Some(12),
            triggering_message: Some(0),
            procedure_criticality: Some(1),
            ies: vec![],
        }),
        Some(CriticalityDiagnostics {
            procedure_code: None,
            triggering_message: Some(2),
            procedure_criticality: None,
            ies: vec![
                IeCriticalityDiagnostics {
                    ie_criticality: nextgcore_s1ap::Criticality::Reject,
                    ie_id: 9999,
                    type_of_error: TypeOfError::NotUnderstood,
                },
                IeCriticalityDiagnostics {
                    ie_criticality: nextgcore_s1ap::Criticality::Notify,
                    ie_id: 8,
                    type_of_error: TypeOfError::Missing,
                },
            ],
        }),
    ]
}

fn error_indications() -> Vec<ErrorIndication> {
    let mut out = Vec::new();
    for mme in [None, Some(0), Some(0xFFFF_FFFF)] {
        for enb in [None, Some(0xFF_FFFF)] {
            for cause in std::iter::once(None).chain(causes().into_iter().map(Some)) {
                for d in diagnostics() {
                    out.push(ErrorIndication {
                        mme_ue_s1ap_id: mme,
                        enb_ue_s1ap_id: enb,
                        cause,
                        criticality_diagnostics: d,
                    });
                }
            }
        }
    }
    out
}

#[test]
fn the_error_indication_matches_the_hand_written_codec() {
    let all = error_indications();
    assert!(all.len() > 1_000, "{}", all.len());
    for ei in all {
        let old = builder::build_error_indication(&ei).unwrap();
        let new = build_error_indication(&ei).unwrap();
        assert_eq!(hex(&new), hex(&old), "{ei:?}");
        let S1apMessage::ErrorIndication(parsed) = decode_s1ap_pdu(&old).unwrap() else {
            panic!("oracle");
        };
        let (decoded, unknown) = decode_error_indication(&old).unwrap();
        assert!(unknown.is_empty());
        assert_eq!(format!("{decoded:?}"), format!("{parsed:?}"));
    }
}

fn connections() -> Vec<Vec<UeAssociatedLogicalS1Connection>> {
    let c = |m: Option<u32>, e: Option<u32>| UeAssociatedLogicalS1Connection {
        mme_ue_s1ap_id: m,
        enb_ue_s1ap_id: e,
    };
    vec![
        vec![c(Some(1), None)],
        vec![c(None, Some(0xFF_FFFF))],
        vec![
            c(Some(0), Some(0)),
            c(Some(0xFFFF_FFFF), None),
            c(None, Some(256)),
        ],
    ]
}

#[test]
fn the_reset_and_its_acknowledge_match_the_hand_written_codec() {
    for list in connections() {
        let ack = ResetAcknowledge {
            ue_associated_connections: list.clone(),
        };
        assert_eq!(
            hex(&build_reset_acknowledge(&ack, &[]).unwrap()),
            hex(&builder::build_reset_acknowledge(&ack).unwrap())
        );
    }
    for cause in causes() {
        let types = std::iter::once(ResetType::S1Interface)
            .chain(connections().into_iter().map(ResetType::PartOfS1Interface));
        for reset_type in types {
            let r = Reset { cause, reset_type };
            let bytes = builder::build_reset(&r).unwrap();
            let S1apMessage::Reset(old) = decode_s1ap_pdu(&bytes).unwrap() else {
                panic!("oracle");
            };
            let Class2Decode::Proceed { msg, .. } = decode_reset(&bytes) else {
                panic!("{r:?}");
            };
            assert_eq!(format!("{msg:?}"), format!("{old:?}"));
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

#[test]
fn a_reset_without_its_reset_type_is_not_run() {
    // Drop the ResetType IE (the last five octets) from the golden.
    let golden = unhex(RESET_ALL);
    let mut bytes = golden[..golden.len() - 5].to_vec();
    bytes[3] -= 5;
    bytes[6] = 1;
    assert!(matches!(
        decode_reset(&bytes),
        Class2Decode::Reject { ies, .. }
            if ies[0].id == ID_RESET_TYPE && ies[0].type_of_error == g::TypeOfError::MISSING
    ));
}

#[test]
fn through_the_handler_a_notify_ie_in_a_reset_is_reported_in_the_acknowledge() {
    let ctx = MmeContext::new();
    let enb = ctx.enb_add("127.0.0.1:36412".parse().unwrap());
    let out = handle_s1ap_message(&ctx, enb, &splice(&unhex(RESET_ALL), 9999, NOTIFY));
    let ack = out
        .iter()
        .find_map(|s| match nextgcore_s1ap_gen::decode(&s.pdu).ok()? {
            g::S1AP_PDU::SuccessfulOutcome(g::SuccessfulOutcome {
                value: g::SuccessfulOutcomeValue::Id_Reset(a),
                ..
            }) => Some(a),
            _ => None,
        })
        .expect("no Reset Acknowledge");
    let diag = ack
        .protocol_i_es
        .0
        .iter()
        .find_map(|ie| match &ie.value {
            g::ResetAcknowledgeProtocolIEs_EntryValue::Id_CriticalityDiagnostics(d) => {
                Some(d.clone())
            }
            _ => None,
        })
        .expect("the acknowledge must carry Criticality Diagnostics");
    assert_eq!(diag.procedure_code, Some(g::ProcedureCode(PROC_RESET)));
}

#[test]
fn through_the_handler_an_error_indication_is_never_answered() {
    let ctx = MmeContext::new();
    let enb = ctx.enb_add("127.0.0.1:36412".parse().unwrap());
    for criticality in [IGNORE, NOTIFY, REJECT] {
        let out = handle_s1ap_message(
            &ctx,
            enb,
            &splice(&unhex(ERROR_INDICATION), 9999, criticality),
        );
        assert!(out.is_empty(), "criticality {criticality}");
    }
}

#[test]
fn the_production_error_indication_is_the_generated_one() {
    let bytes = crate::s1ap_build::build_error_indication(
        Some(1),
        Some(1),
        S1apCauseGroup::Nas,
        crate::s1ap_build::nas_cause::DETACH,
        None,
    )
    .unwrap();
    assert_eq!(hex(&bytes), ERROR_INDICATION);
}
