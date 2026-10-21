//! #514 stage 3: NAS transport on the generated codec.
//!
//! Oracle: the pre-change hand-written encoder and parser. Goldens: nextgcore-
//! s1ap's `golden_x691.rs` (derived by hand from X.691 in #456).

use super::*;
use crate::context::MmeContext;
use crate::s1ap_build::{self, hand_written_build_downlink_nas_transport};
use crate::s1ap_handler::handle_s1ap_message;
use nextgcore_s1ap::{
    EutranCgi, InitialUeMessage, RrcEstablishmentCause, S1apMessage, STmsi, Tai, UlNasTransport,
};
use nextgcore_s1ap_oracle::{builder, decode_s1ap_pdu};

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
const INITIAL_UE_MESSAGE: &str = "000c402b000005000800020001001a0003020741004300060099f9070001006440080099f9070019b0100086400130";
const DOWNLINK_NAS_TRANSPORT: &str = "000b4016000003000000020001000800020001001a0003020752";
const UPLINK_NAS_TRANSPORT: &str = "000d402c000005000000020001000800020001001a0003020753006440080099f9070019b010004340060099f9070001";

fn tai(tac: u16) -> Tai {
    Tai {
        plmn_identity: PLMN,
        tac,
    }
}

fn cgi(cell: u32) -> EutranCgi {
    EutranCgi {
        plmn_identity: PLMN,
        cell_identity: cell,
    }
}

const NAS_LENS: [usize; 7] = [1, 2, 127, 128, 255, 1000, 16_000];
const IDS: [(u32, u32); 3] = [(0, 0), (1, 1), (0xFF_FFFF, 0xFFFF_FFFF)];

#[test]
fn the_downlink_nas_transport_is_the_x691_golden() {
    let bytes = s1ap_build::build_downlink_nas_transport_with_ids(1, 1, &[0x07, 0x52]).unwrap();
    assert_eq!(hex(&bytes), DOWNLINK_NAS_TRANSPORT);
}

#[test]
fn the_downlink_nas_transport_matches_the_hand_written_encoder() {
    let mut cases = 0;
    for len in NAS_LENS {
        for (enb, mme) in IDS {
            let nas = vec![0x5A; len];
            assert_eq!(
                s1ap_build::build_downlink_nas_transport_with_ids(enb, mme, &nas).unwrap(),
                hand_written_build_downlink_nas_transport(enb, mme, &nas).unwrap(),
                "len {len}, ids {enb}/{mme}"
            );
            cases += 1;
        }
    }
    assert_eq!(cases, 21);
}

/// The hand-written encoder refused a value past 16,383 octets (no X.691
/// §11.9.3.8 fragmentation), so mmed could not send a NAS-PDU of ~16 KB.
#[test]
fn a_downlink_nas_pdu_past_16k_is_now_sent() {
    let nas = vec![0x5A; 70_000];
    assert!(hand_written_build_downlink_nas_transport(1, 1, &nas).is_err());
    let bytes = s1ap_build::build_downlink_nas_transport_with_ids(1, 1, &nas).unwrap();
    let g::S1AP_PDU::InitiatingMessage(m) = nextgcore_s1ap_gen::decode(&bytes).unwrap() else {
        panic!()
    };
    let g::InitiatingMessageValue::Id_downlinkNASTransport(d) = m.value else {
        panic!()
    };
    assert!(d.protocol_i_es.0.iter().any(|ie| matches!(
        &ie.value,
        g::DownlinkNASTransportProtocolIEs_EntryValue::Id_NAS_PDU(n) if n.0 == nas
    )));
}

fn initial_ue_messages() -> Vec<InitialUeMessage> {
    let mut out = Vec::new();
    for len in NAS_LENS {
        for (enb, _) in IDS {
            for s_tmsi in [
                None,
                Some(STmsi { mmec: 0, m_tmsi: 0 }),
                Some(STmsi {
                    mmec: 0xFF,
                    m_tmsi: 0xDEAD_BEEF,
                }),
            ] {
                for cause in [
                    RrcEstablishmentCause::Emergency,
                    RrcEstablishmentCause::HighPriorityAccess,
                    RrcEstablishmentCause::MtAccess,
                    RrcEstablishmentCause::MoSignalling,
                    RrcEstablishmentCause::MoData,
                ] {
                    out.push(InitialUeMessage {
                        enb_ue_s1ap_id: enb,
                        nas_pdu: vec![0x17; len],
                        tai: tai(u16::try_from(len % 0x1_0000).unwrap()),
                        eutran_cgi: cgi(0x0FFF_FFFF & enb.wrapping_mul(7)),
                        rrc_establishment_cause: cause,
                        s_tmsi,
                    });
                }
            }
        }
    }
    out
}

#[test]
fn the_initial_ue_message_decodes_as_the_hand_written_parser_reads_it() {
    let msgs = initial_ue_messages();
    assert_eq!(msgs.len(), 7 * 3 * 3 * 5);
    for msg in &msgs {
        let bytes = builder::build_initial_ue_message(msg).unwrap();
        let Class2Decode::Proceed { msg: got, notify } = decode_initial_ue_message(&bytes) else {
            panic!("generated refused {msg:?}")
        };
        assert!(notify.is_empty());
        let S1apMessage::InitialUeMessage(old) = decode_s1ap_pdu(&bytes).unwrap() else {
            panic!()
        };
        assert_eq!(format!("{got:?}"), format!("{old:?}"));
        assert_eq!(format!("{got:?}"), format!("{msg:?}"));
    }
    let Class2Decode::Proceed { msg, .. } = decode_initial_ue_message(&unhex(INITIAL_UE_MESSAGE))
    else {
        panic!("golden refused")
    };
    assert_eq!(msg.nas_pdu, [0x07, 0x41]);
}

#[test]
fn the_uplink_nas_transport_decodes_as_the_hand_written_parser_reads_it() {
    let mut cases = 0;
    for len in NAS_LENS {
        for (enb, mme) in IDS {
            let msg = UlNasTransport {
                mme_ue_s1ap_id: mme,
                enb_ue_s1ap_id: enb,
                nas_pdu: vec![0x27; len],
                eutran_cgi: cgi(0x0ABC_DEF0),
                tai: tai(0xFFFF),
            };
            let bytes = builder::build_uplink_nas_transport(&msg).unwrap();
            let Class2Decode::Proceed { msg: got, notify } = decode_uplink_nas_transport(&bytes)
            else {
                panic!("generated refused {msg:?}")
            };
            assert!(notify.is_empty());
            let S1apMessage::UplinkNasTransport(old) = decode_s1ap_pdu(&bytes).unwrap() else {
                panic!()
            };
            assert_eq!(
                (got.mme_ue_s1ap_id, got.enb_ue_s1ap_id, &got.nas_pdu),
                (old.mme_ue_s1ap_id, old.enb_ue_s1ap_id, &old.nas_pdu)
            );
            assert_eq!(got.eutran_cgi, Some(old.eutran_cgi.clone()));
            assert_eq!(got.tai, Some(old.tai.clone()));
            cases += 1;
        }
    }
    assert_eq!(cases, 21);
    assert!(matches!(
        decode_uplink_nas_transport(&unhex(UPLINK_NAS_TRANSPORT)),
        Class2Decode::Proceed { .. }
    ));
}

/// Rebuild the golden Initial UE Message with the generated codec, letting
/// `edit` change its IE list.
fn initial_ue_with(edit: impl FnOnce(&mut Vec<g::InitialUEMessageProtocolIEs_Entry>)) -> Vec<u8> {
    let g::S1AP_PDU::InitiatingMessage(mut m) =
        nextgcore_s1ap_gen::decode(&unhex(INITIAL_UE_MESSAGE)).unwrap()
    else {
        panic!()
    };
    let g::InitiatingMessageValue::Id_initialUEMessage(ref mut v) = m.value else {
        panic!()
    };
    edit(&mut v.protocol_i_es.0);
    nextgcore_s1ap_gen::encode(&g::S1AP_PDU::InitiatingMessage(m)).unwrap()
}

/// delay-tolerantAccess, mo-VoiceCall and mo-ExceptionData are ENUMERATED
/// extension values the hand-written parser refused, so mmed dropped every
/// INITIAL UE MESSAGE carrying one. They now proceed.
#[test]
fn extension_rrc_establishment_causes_are_accepted() {
    for (value, cause) in [
        (5u8, RrcEstablishmentCause::DelayTolerantAccess),
        (6, RrcEstablishmentCause::MoVoiceCall),
        (7, RrcEstablishmentCause::MoExceptionData),
    ] {
        let bytes = initial_ue_with(|ies| {
            for ie in ies {
                if let g::InitialUEMessageProtocolIEs_EntryValue::Id_RRC_Establishment_Cause(c) =
                    &mut ie.value
                {
                    c.0 = value;
                }
            }
        });
        assert!(
            decode_s1ap_pdu(&bytes).is_err(),
            "the hand-written parser now accepts {value}"
        );
        let Class2Decode::Proceed { msg, .. } = decode_initial_ue_message(&bytes) else {
            panic!("cause {value} refused")
        };
        assert_eq!(msg.rrc_establishment_cause, cause);
    }
}

#[test]
fn a_missing_reject_ie_rejects_and_a_missing_ignore_ie_is_ignored() {
    // NAS-PDU (reject) missing.
    let bytes = initial_ue_with(|ies| ies.retain(|ie| ie.id.0 != 26));
    let Class2Decode::Reject {
        ies,
        enb_ue_s1ap_id,
        ..
    } = decode_initial_ue_message(&bytes)
    else {
        panic!("proceeded without a NAS-PDU")
    };
    assert_eq!(enb_ue_s1ap_id, Some(1));
    assert_eq!(
        ies,
        vec![DiagnosedIe {
            criticality: REJECT,
            id: 26,
            type_of_error: g::TypeOfError::MISSING
        }]
    );
    // EUTRAN-CGI (ignore) missing: proceeds.
    let bytes = initial_ue_with(|ies| ies.retain(|ie| ie.id.0 != 100));
    let Class2Decode::Proceed { msg, notify } = decode_initial_ue_message(&bytes) else {
        panic!("a missing ignore IE rejected")
    };
    assert!(notify.is_empty());
    assert_eq!(msg.eutran_cgi.cell_identity, 0);
}

/// Splice an unknown IE `id`/`criticality` after the IE count of an
/// initiating message with a one-octet open-type length.
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

fn outcome(b: &[u8]) -> (bool, Vec<DiagnosedIe>) {
    let class2 = |d: Class2Decode<()>| match d {
        Class2Decode::Proceed { notify, .. } => (true, notify),
        Class2Decode::Reject { ies, .. } => (false, ies),
        Class2Decode::Undecodable => panic!("undecodable"),
    };
    if b[1] == PROC_INITIAL_UE_MESSAGE {
        class2(match decode_initial_ue_message(b) {
            Class2Decode::Proceed { notify, .. } => Class2Decode::Proceed { msg: (), notify },
            Class2Decode::Reject {
                ies,
                enb_ue_s1ap_id,
                mme_ue_s1ap_id,
            } => Class2Decode::Reject {
                ies,
                enb_ue_s1ap_id,
                mme_ue_s1ap_id,
            },
            Class2Decode::Undecodable => Class2Decode::Undecodable,
        })
    } else {
        class2(match decode_uplink_nas_transport(b) {
            Class2Decode::Proceed { notify, .. } => Class2Decode::Proceed { msg: (), notify },
            Class2Decode::Reject {
                ies,
                enb_ue_s1ap_id,
                mme_ue_s1ap_id,
            } => Class2Decode::Reject {
                ies,
                enb_ue_s1ap_id,
                mme_ue_s1ap_id,
            },
            Class2Decode::Undecodable => Class2Decode::Undecodable,
        })
    }
}

#[test]
fn unknown_ies_in_nas_transport_are_handled_by_criticality() {
    for golden in [INITIAL_UE_MESSAGE, UPLINK_NAS_TRANSPORT] {
        let base = unhex(golden);
        assert_eq!(outcome(&splice(&base, 9999, IGNORE)), (true, vec![]));
        let (ran, notify) = outcome(&splice(&base, 9999, NOTIFY));
        assert!(ran);
        assert_eq!(notify[0].id, 9999);
        let (ran, ies) = outcome(&splice(&base, 9999, REJECT));
        assert!(!ran);
        assert_eq!(ies[0].id, 9999);
    }
}

fn error_indication_ie_ids(pdu: &[u8]) -> Option<Vec<u16>> {
    match decode_s1ap_pdu(pdu).ok()? {
        S1apMessage::ErrorIndication(ei) => Some(
            ei.criticality_diagnostics
                .map(|d| d.ies.iter().map(|i| i.ie_id).collect())
                .unwrap_or_default(),
        ),
        _ => None,
    }
}

#[test]
fn through_the_handler_a_reject_ie_gets_an_error_indication_and_no_ue() {
    let ctx = MmeContext::new();
    let enb = ctx.enb_add("127.0.0.1:36412".parse().unwrap());
    let before = ctx.enb_ue_pool.read().unwrap().len();
    let out = handle_s1ap_message(&ctx, enb, &splice(&unhex(INITIAL_UE_MESSAGE), 9999, REJECT));
    assert_eq!(out.len(), 1);
    assert_eq!(error_indication_ie_ids(&out[0].pdu), Some(vec![9999]));
    assert_eq!(
        ctx.enb_ue_pool.read().unwrap().len(),
        before,
        "a UE context was created"
    );
}

#[test]
fn through_the_handler_a_notify_ie_gets_an_error_indication_and_the_ue_is_served() {
    let ctx = MmeContext::new();
    let enb = ctx.enb_add("127.0.0.1:36412".parse().unwrap());
    let before = ctx.enb_ue_pool.read().unwrap().len();
    let out = handle_s1ap_message(&ctx, enb, &splice(&unhex(INITIAL_UE_MESSAGE), 9999, NOTIFY));
    assert!(out
        .iter()
        .any(|s| error_indication_ie_ids(&s.pdu) == Some(vec![9999])));
    assert_eq!(
        ctx.enb_ue_pool.read().unwrap().len(),
        before + 1,
        "no UE context"
    );
}

#[test]
fn through_the_handler_an_uplink_nas_for_an_unknown_ue_still_gets_an_error_indication() {
    let ctx = MmeContext::new();
    let enb = ctx.enb_add("127.0.0.1:36412".parse().unwrap());
    let out = handle_s1ap_message(&ctx, enb, &unhex(UPLINK_NAS_TRANSPORT));
    assert_eq!(out.len(), 1);
    assert!(error_indication_ie_ids(&out[0].pdu).is_some());
}
