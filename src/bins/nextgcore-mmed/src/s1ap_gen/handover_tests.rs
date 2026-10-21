//! #514 stage 8a: the handover family's simpler half on the generated codec.
//!
//! Oracle: the pre-change hand-written builders and parser
//! (`test_codec::builder`, `decode_s1ap_pdu`: since #514 stage 13b the generated codec with an independently written domain mapping, and builders for messages mmed sends check that their output decodes back to their input). Golden: octets derived by
//! hand from X.691 (APER) for TS 36.413 §9.1.5.3, §9.1.5.6 and §9.1.5.11.

use super::*;
use crate::context::{MmeContext, S1apCauseGroup};
use crate::s1ap_build::cause_to_s1ap;
use crate::s1ap_gen::test_codec::{builder, decode_s1ap_pdu};
use crate::s1ap_handler::handle_s1ap_message;
use nextgcore_s1ap::{
    CauseNas, EnbStatusTransfer, HandoverCancel, HandoverCancelAcknowledge, HandoverFailure,
    HandoverNotify, HandoverPreparationFailure, MmeStatusTransfer, S1apMessage,
};

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// ENB-StatusTransfer-TransparentContainer with one bearer: E-RAB 5, UL COUNT
/// (PDCP-SN 1, HFN 2), DL COUNT (PDCP-SN 3, HFN 4), no receive status.
///
/// Container SEQUENCE ext 0, iE-Extensions absent 0, pad; list SIZE(1..256)
/// count-1 = 0 in one aligned octet: `00 00`. Item IE 89 `00 59 | 40 | 0b`
/// (ignore). Item: ext 0, receiveStatus absent 0, iE-Ext absent 0, E-RAB-ID
/// (0..15, ...) ext 0 and `0101` = `05`. Each COUNTvalue: ext 0, iE-Ext 0,
/// pad `00`; PDCP-SN (0..4095) two aligned octets; HFN (0..1048575) octet
/// count-1 in 2 bits `00`, pad, then one octet. UL `00 00 01 00 02`, DL
/// `00 00 03 00 04`.
const CONTAINER: &str = "00000059400b0500000100020000030004";

fn container_value() -> g::ENB_StatusTransfer_TransparentContainer {
    let count = |pdcp_sn: u16, hfn: u32| g::COUNTvalue {
        pdcp_sn: g::PDCP_SN(pdcp_sn),
        hfn: g::HFN(hfn),
        ie_extensions: None,
    };
    g::ENB_StatusTransfer_TransparentContainer {
        bearers_subject_to_status_transfer_list: g::Bearers_SubjectToStatusTransferList(vec![
            g::Bearers_SubjectToStatusTransferList_Entry {
                id: g::ProtocolIE_ID(89),
                criticality: g::Criticality(IGNORE),
                value:
                    g::Bearers_SubjectToStatusTransferList_EntryValue::Id_Bearers_SubjectToStatusTransfer_Item(
                        g::Bearers_SubjectToStatusTransfer_Item {
                            e_rab_id: g::E_RAB_ID(5),
                            ul_coun_tvalue: count(1, 2),
                            dl_coun_tvalue: count(3, 4),
                            receive_statusof_ulpdcpsd_us: None,
                            ie_extensions: None,
                        },
                    ),
            },
        ]),
        ie_extensions: None,
    }
}

/// A valid status transfer container, as the raw APER the hand-written types
/// carry.
pub(crate) fn sample_container() -> Vec<u8> {
    status_container_raw(&container_value()).unwrap()
}

#[test]
fn the_status_container_is_the_x691_golden() {
    assert_eq!(hex(&sample_container()), CONTAINER);
    let back = status_container_from(&sample_container()).unwrap();
    assert_eq!(back, container_value());
}

/// HANDOVER CANCEL ACKNOWLEDGE, MME 1 / eNB 1: `20 04 00 0f`, `00 00 02`, the
/// two IDs at criticality ignore (`40`), each one-octet length `00` and `01`.
const CANCEL_ACK: &str = "2004000f000002000040020001000840020001";
/// HANDOVER PREPARATION FAILURE, MME 1 / eNB 1, Cause nas / normal-release:
/// `40 00 00 14`, `00 00 03`, the IDs at ignore, Cause IE 2 at ignore `40`,
/// length 1, `0 010 0 00` and pad = `20`.
const PREP_FAILURE: &str = "400000140000030000400200010008400200010002400120";

#[test]
fn the_cancel_ack_and_prep_failure_are_the_x691_goldens() {
    let ack = build_handover_cancel_acknowledge(
        &HandoverCancelAcknowledge {
            mme_ue_s1ap_id: 1,
            enb_ue_s1ap_id: 1,
        },
        &[],
    )
    .unwrap();
    assert_eq!(hex(&ack), CANCEL_ACK);
    let failure = build_handover_preparation_failure(&HandoverPreparationFailure {
        mme_ue_s1ap_id: 1,
        enb_ue_s1ap_id: 1,
        cause: Cause::Nas(CauseNas::NormalRelease),
    })
    .unwrap();
    assert_eq!(hex(&failure), PREP_FAILURE);
}

const IDS: [(u32, u32); 4] = [(0, 0), (1, 1), (65_536, 256), (0xFFFF_FFFF, 0xFF_FFFF)];

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
fn the_encodes_match_the_hand_written_encoder() {
    let mut cases = 0;
    for (mme, enb) in IDS {
        for cause in causes() {
            let f = HandoverPreparationFailure {
                mme_ue_s1ap_id: mme,
                enb_ue_s1ap_id: enb,
                cause,
            };
            assert_eq!(
                hex(&build_handover_preparation_failure(&f).unwrap()),
                hex(&builder::build_handover_preparation_failure(&f).unwrap()),
                "{f:?}"
            );
            cases += 1;
        }
        let a = HandoverCancelAcknowledge {
            mme_ue_s1ap_id: mme,
            enb_ue_s1ap_id: enb,
        };
        assert_eq!(
            hex(&build_handover_cancel_acknowledge(&a, &[]).unwrap()),
            hex(&builder::build_handover_cancel_acknowledge(&a).unwrap())
        );
        let s = MmeStatusTransfer {
            mme_ue_s1ap_id: mme,
            enb_ue_s1ap_id: enb,
            status_transfer_container: sample_container(),
        };
        assert_eq!(
            hex(&build_mme_status_transfer(&s).unwrap()),
            hex(&builder::build_mme_status_transfer(&s).unwrap())
        );
        cases += 2;
    }
    assert!(cases > 200, "{cases}");
}

#[test]
fn the_decodes_read_as_the_hand_written_parser_reads_them() {
    for (mme, enb) in IDS {
        let st = builder::build_enb_status_transfer(&EnbStatusTransfer {
            mme_ue_s1ap_id: mme,
            enb_ue_s1ap_id: enb,
            status_transfer_container: sample_container(),
        })
        .unwrap();
        let S1apMessage::EnbStatusTransfer(old) = decode_s1ap_pdu(&st).unwrap() else {
            panic!("oracle");
        };
        let Class2Decode::Proceed { msg, .. } = decode_enb_status_transfer(&st) else {
            panic!("status transfer");
        };
        assert_eq!(format!("{msg:?}"), format!("{old:?}"));

        let n = HandoverNotify {
            mme_ue_s1ap_id: mme,
            enb_ue_s1ap_id: enb,
            eutran_cgi: EutranCgi {
                plmn_identity: [0x99, 0xF9, 0x07],
                cell_identity: 0x0FFF_FFFF,
            },
            tai: Tai {
                plmn_identity: [0x99, 0xF9, 0x07],
                tac: 0xBEEF,
            },
        };
        let Class2Decode::Proceed { msg, .. } =
            decode_handover_notify(&builder::build_handover_notify(&n).unwrap())
        else {
            panic!("notify");
        };
        assert_eq!(
            msg,
            HandoverNotifyAt {
                mme_ue_s1ap_id: mme,
                enb_ue_s1ap_id: enb,
                location: Some((n.tai, n.eutran_cgi)),
            }
        );

        for cause in causes() {
            let c = HandoverCancel {
                mme_ue_s1ap_id: mme,
                enb_ue_s1ap_id: enb,
                cause,
            };
            let bytes = builder::build_handover_cancel(&c).unwrap();
            let S1apMessage::HandoverCancel(old) = decode_s1ap_pdu(&bytes).unwrap() else {
                panic!("oracle");
            };
            let Class2Decode::Proceed { msg, .. } = decode_handover_cancel(&bytes) else {
                panic!("cancel");
            };
            assert_eq!(format!("{msg:?}"), format!("{old:?}"));

            let f = builder::build_handover_failure(&HandoverFailure {
                mme_ue_s1ap_id: mme,
                cause,
            })
            .unwrap();
            let S1apMessage::HandoverFailure(old) = decode_s1ap_pdu(&f).unwrap() else {
                panic!("oracle");
            };
            let ResponseDecode::Decoded { msg, .. } = decode_handover_failure(&f) else {
                panic!("failure");
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

fn notify_bytes() -> Vec<u8> {
    builder::build_handover_notify(&HandoverNotify {
        mme_ue_s1ap_id: 1,
        enb_ue_s1ap_id: 1,
        eutran_cgi: EutranCgi {
            plmn_identity: [0x00, 0xF1, 0x10],
            cell_identity: 1,
        },
        tai: Tai {
            plmn_identity: [0x00, 0xF1, 0x10],
            tac: 1,
        },
    })
    .unwrap()
}

#[test]
fn unknown_and_missing_ies_are_handled_by_criticality() {
    // HANDOVER NOTIFY: TAI is ignore, so without it the handover still completes.
    let Class2Decode::Proceed { msg, .. } =
        decode_handover_notify(&remove(&notify_bytes(), ID_TAI))
    else {
        panic!("a missing ignore IE must not stop the notify");
    };
    assert_eq!(msg.location, None);
    // ... and eNB-UE-S1AP-ID is reject.
    assert!(matches!(
        decode_handover_notify(&remove(&notify_bytes(), ID_ENB_UE_S1AP_ID)),
        Class2Decode::Reject { ies, .. } if ies[0].id == ID_ENB_UE_S1AP_ID
    ));
    assert!(matches!(
        decode_handover_notify(&splice(&notify_bytes(), 9999, NOTIFY)),
        Class2Decode::Proceed { notify, .. } if notify[0].id == 9999
    ));
    let st = builder::build_enb_status_transfer(&EnbStatusTransfer {
        mme_ue_s1ap_id: 1,
        enb_ue_s1ap_id: 1,
        status_transfer_container: sample_container(),
    })
    .unwrap();
    assert!(matches!(
        decode_enb_status_transfer(&splice(&st, 9999, REJECT)),
        Class2Decode::Reject { ies, .. } if ies[0].id == 9999
    ));
    let f = builder::build_handover_failure(&HandoverFailure {
        mme_ue_s1ap_id: 1,
        cause: Cause::Nas(CauseNas::Unspecified),
    })
    .unwrap();
    assert!(matches!(
        decode_handover_failure(&splice(&f, 9999, REJECT)),
        ResponseDecode::Failed(_)
    ));
}

#[test]
fn a_notify_ie_in_a_handover_cancel_is_reported_in_the_acknowledge() {
    let ctx = MmeContext::new();
    let enb = ctx.enb_add("127.0.0.1:36412".parse().unwrap());
    let enb_ue_id = ctx.enb_ue_add(enb, 7);
    let mme_ue_id = ctx.mme_ue_add(enb_ue_id);
    ctx.enb_ue_associate_mme_ue(enb_ue_id, mme_ue_id);
    let mme = ctx.enb_ue_find_by_id(enb_ue_id).unwrap().mme_ue_s1ap_id;
    let cancel = builder::build_handover_cancel(&HandoverCancel {
        mme_ue_s1ap_id: mme,
        enb_ue_s1ap_id: 7,
        cause: Cause::Nas(CauseNas::Unspecified),
    })
    .unwrap();
    let out = handle_s1ap_message(&ctx, enb, &splice(&cancel, 9999, NOTIFY));
    let ack = out
        .iter()
        .find_map(|s| match nextgcore_s1ap_gen::decode(&s.pdu).ok()? {
            g::S1AP_PDU::SuccessfulOutcome(g::SuccessfulOutcome {
                value: g::SuccessfulOutcomeValue::Id_HandoverCancel(a),
                ..
            }) => Some(a),
            _ => None,
        })
        .expect("no Handover Cancel Acknowledge");
    let diag = ack
        .protocol_i_es
        .0
        .iter()
        .find_map(|ie| match &ie.value {
            g::HandoverCancelAcknowledgeProtocolIEs_EntryValue::Id_CriticalityDiagnostics(d) => {
                Some(d.clone())
            }
            _ => None,
        })
        .expect("the acknowledge must carry Criticality Diagnostics");
    assert_eq!(
        diag.procedure_code,
        Some(g::ProcedureCode(PROC_HANDOVER_CANCEL))
    );
    assert_eq!(
        diag.i_es_criticality_diagnostics.unwrap().0[0].ie_id,
        g::ProtocolIE_ID(9999)
    );
}

#[test]
fn a_status_container_that_is_not_the_asn1_type_is_not_relayed() {
    // The hand-written encoder relayed any octets as the container; the
    // generated one requires an ENB-StatusTransfer-TransparentContainer.
    assert!(build_mme_status_transfer(&MmeStatusTransfer {
        mme_ue_s1ap_id: 1,
        enb_ue_s1ap_id: 1,
        status_transfer_container: vec![0x00, 0x01, 0xF0, 0x0D, 0x7F, 0x80, 0x2A],
    })
    .is_err());
}
