//! #514 stage 4: Initial Context Setup on the generated codec.
//!
//! #737: since the hand-written encoder was deleted (#560), the
//! `*_with_schema_criticalities` tests below compare the production encoder
//! with itself and check it decodes back; what pins each IE criticality is
//! `criticality_oracle`, which checks every PDU a production builder encodes
//! against the TS 36.413 §9.3 object sets.
//!
//! Oracle: the pre-change hand-written builders and parser
//! (`test_codec::builder`, `decode_s1ap_pdu`: since #514 stage 13b the generated codec with an independently written domain mapping, and builders for messages mmed sends check that their output decodes back to their input). Golden: nextgcore-s1ap's
//! `golden_x691.rs` Initial Context Setup Request (derived by hand from X.691
//! in #456).

use super::*;
use crate::context::MmeContext;
use crate::s1ap_gen::test_codec::{builder, decode_s1ap_pdu};
use crate::s1ap_handler::handle_s1ap_message;
use nextgcore_s1ap::{
    AllocationRetentionPriority, CauseMisc, CauseNas, CauseRadioNetwork, ErabFailedItem,
    ErabLevelQosParameters, ErabSetupItem, ErabToBeSetupItem, GbrQosInformation,
    InitialContextSetupFailure, InitialContextSetupRequest, InitialContextSetupResponse,
    S1apMessage, UeAmbr, UeSecurityCapabilities,
};

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

const INITIAL_CONTEXT_SETUP_REQUEST: &str = "0009005d000006000000020001000800020001004200060803e82003e800180013000034000e050009040f800a00000100000001006b000518000c0000004900200000000000000000000000000000000000000000000000000000000000000000";

fn golden_request() -> InitialContextSetupRequest {
    InitialContextSetupRequest {
        mme_ue_s1ap_id: 1,
        enb_ue_s1ap_id: 1,
        ue_ambr: UeAmbr { dl: 1000, ul: 1000 },
        erab_list: vec![ErabToBeSetupItem {
            erab_id: 5,
            erab_qos: ErabLevelQosParameters {
                qci: 9,
                arp: AllocationRetentionPriority {
                    priority_level: 1,
                    pre_emption_capability: false,
                    pre_emption_vulnerability: false,
                },
                gbr_qos_info: None,
            },
            transport_layer_address: vec![10, 0, 0, 1],
            gtp_teid: 1,
            nas_pdu: None,
        }],
        ue_security_capabilities: UeSecurityCapabilities {
            encryption_algorithms: 0xC000,
            integrity_algorithms: 0xC000,
        },
        security_key: [0u8; 32],
    }
}

#[test]
fn the_request_is_the_x691_golden() {
    assert_eq!(
        hex(&build_initial_context_setup_request(&golden_request()).unwrap()),
        INITIAL_CONTEXT_SETUP_REQUEST
    );
}

fn requests() -> Vec<InitialContextSetupRequest> {
    let mut out = Vec::new();
    for erabs in [1usize, 2, 3, 16] {
        for gbr in [false, true] {
            for nas in [None, Some(1usize), Some(300)] {
                for addr in [
                    vec![10, 0, 0, 1],
                    (0u8..16).collect::<Vec<_>>(),
                    (0u8..20).collect(),
                ] {
                    for (ambr, algs) in [((0, 0), (0, 0)), ((10_000_000_000, 1), (0xE000, 0x6000))]
                    {
                        out.push(InitialContextSetupRequest {
                            mme_ue_s1ap_id: 0xFFFF_FFFF,
                            enb_ue_s1ap_id: 0xFF_FFFF,
                            ue_ambr: UeAmbr {
                                dl: ambr.0,
                                ul: ambr.1,
                            },
                            erab_list: (0..erabs)
                                .map(|i| ErabToBeSetupItem {
                                    erab_id: u8::try_from(i % 16).unwrap(),
                                    erab_qos: ErabLevelQosParameters {
                                        qci: if gbr { 1 } else { 255 },
                                        arp: AllocationRetentionPriority {
                                            priority_level: u8::try_from(i % 16).unwrap(),
                                            pre_emption_capability: i % 2 == 0,
                                            pre_emption_vulnerability: i % 3 == 0,
                                        },
                                        gbr_qos_info: gbr.then_some(GbrQosInformation {
                                            erab_max_bitrate_dl: 10_000_000_000,
                                            erab_max_bitrate_ul: 0,
                                            erab_guaranteed_bitrate_dl: 64_000,
                                            erab_guaranteed_bitrate_ul: 1,
                                        }),
                                    },
                                    transport_layer_address: addr.clone(),
                                    gtp_teid: 0xFFFF_FFFF - u32::try_from(i).unwrap(),
                                    nas_pdu: nas.map(|n| vec![0x27; n]),
                                })
                                .collect(),
                            ue_security_capabilities: UeSecurityCapabilities {
                                encryption_algorithms: algs.0,
                                integrity_algorithms: algs.1,
                            },
                            security_key: [0xA5; 32],
                        });
                    }
                }
            }
        }
    }
    out
}

#[test]
fn the_request_round_trips_with_schema_criticalities() {
    let reqs = requests();
    assert_eq!(reqs.len(), 4 * 2 * 3 * 3 * 2);
    for req in &reqs {
        assert_eq!(
            build_initial_context_setup_request(req).unwrap(),
            builder::build_initial_context_setup_request(req).unwrap(),
            "{} E-RABs, gbr {}, addr {} octets",
            req.erab_list.len(),
            req.erab_list[0].erab_qos.gbr_qos_info.is_some(),
            req.erab_list[0].transport_layer_address.len()
        );
    }
}

fn responses() -> Vec<InitialContextSetupResponse> {
    let mut out = Vec::new();
    for setup in [1usize, 2, 16] {
        for failed in [0usize, 1, 3] {
            for addr in [vec![10, 0, 0, 2], (0u8..16).collect::<Vec<_>>()] {
                out.push(InitialContextSetupResponse {
                    mme_ue_s1ap_id: 7,
                    enb_ue_s1ap_id: 0xFF_FFFF,
                    erab_setup_list: (0..setup)
                        .map(|i| ErabSetupItem {
                            erab_id: u8::try_from(i % 16).unwrap(),
                            transport_layer_address: addr.clone(),
                            gtp_teid: 0x1234_5600 + u32::try_from(i).unwrap(),
                        })
                        .collect(),
                    erab_failed_list: (0..failed)
                        .map(|i| ErabFailedItem {
                            erab_id: u8::try_from(i).unwrap(),
                            cause: match i {
                                0 => Cause::RadioNetwork(CauseRadioNetwork::Unspecified),
                                1 => Cause::Nas(CauseNas::Detach),
                                _ => Cause::Misc(CauseMisc::HardwareFailure),
                            },
                        })
                        .collect(),
                });
            }
        }
    }
    out
}

#[test]
fn the_response_decodes_as_the_hand_written_parser_reads_it() {
    let rsps = responses();
    assert_eq!(rsps.len(), 18);
    for rsp in &rsps {
        let bytes = builder::build_initial_context_setup_response(rsp).unwrap();
        let ResponseDecode::Decoded { msg, notify } = decode_initial_context_setup_response(&bytes)
        else {
            panic!("generated refused {rsp:?}")
        };
        assert!(notify.is_empty());
        let S1apMessage::InitialContextSetupResponse(old) = decode_s1ap_pdu(&bytes).unwrap() else {
            panic!()
        };
        assert_eq!(format!("{msg:?}"), format!("{old:?}"));
        assert_eq!(format!("{msg:?}"), format!("{rsp:?}"));
    }
}

#[test]
fn the_failure_decodes_as_the_hand_written_parser_reads_it() {
    let mut cases = 0;
    for cause in [
        Cause::RadioNetwork(CauseRadioNetwork::Unspecified),
        Cause::Nas(CauseNas::NormalRelease),
        Cause::Misc(CauseMisc::UnknownPlmn),
    ] {
        for (mme, enb) in [(0u32, 0u32), (0xFFFF_FFFF, 0xFF_FFFF)] {
            let f = InitialContextSetupFailure {
                mme_ue_s1ap_id: mme,
                enb_ue_s1ap_id: enb,
                cause,
            };
            let bytes = builder::build_initial_context_setup_failure(&f).unwrap();
            let ResponseDecode::Decoded { msg, .. } = decode_initial_context_setup_failure(&bytes)
            else {
                panic!("refused {f:?}")
            };
            let S1apMessage::InitialContextSetupFailure(old) = decode_s1ap_pdu(&bytes).unwrap()
            else {
                panic!()
            };
            assert_eq!(format!("{msg:?}"), format!("{old:?}"));
            cases += 1;
        }
    }
    assert_eq!(cases, 6);
}

/// Splice an unknown IE after the IE count of a successful/unsuccessful
/// outcome with a one-octet open-type length.
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
fn unknown_ies_in_the_response_are_handled_by_criticality() {
    let base = builder::build_initial_context_setup_response(&responses()[0]).unwrap();
    assert!(matches!(
        decode_initial_context_setup_response(&splice(&base, 9999, IGNORE)),
        ResponseDecode::Decoded { notify, .. } if notify.is_empty()
    ));
    assert!(matches!(
        decode_initial_context_setup_response(&splice(&base, 9999, NOTIFY)),
        ResponseDecode::Decoded { notify, .. } if notify.len() == 1 && notify[0].id == 9999
    ));
    assert!(matches!(
        decode_initial_context_setup_response(&splice(&base, 9999, REJECT)),
        ResponseDecode::Failed(ies) if ies[0].id == 9999
    ));
}

#[test]
fn through_the_handler_a_notify_ie_in_the_response_is_reported() {
    let ctx = MmeContext::new();
    let enb = ctx.enb_add("127.0.0.1:36412".parse().unwrap());
    let base = builder::build_initial_context_setup_response(&responses()[0]).unwrap();
    let out = handle_s1ap_message(&ctx, enb, &splice(&base, 9999, NOTIFY));
    let ei = out
        .iter()
        .find_map(|s| match decode_s1ap_pdu(&s.pdu).ok()? {
            S1apMessage::ErrorIndication(ei) => Some(ei),
            _ => None,
        })
        .expect("no Error Indication");
    let diag = ei.criticality_diagnostics.unwrap();
    assert_eq!(diag.procedure_code, Some(PROC_INITIAL_CONTEXT_SETUP));
    assert_eq!(
        diag.triggering_message,
        Some(nextgcore_s1ap::triggering_message::SUCCESSFUL_OUTCOME)
    );
    assert_eq!(diag.ies[0].ie_id, 9999);
}

#[test]
fn through_the_handler_a_reject_ie_in_the_response_sends_nothing() {
    let ctx = MmeContext::new();
    let enb = ctx.enb_add("127.0.0.1:36412".parse().unwrap());
    let base = builder::build_initial_context_setup_response(&responses()[0]).unwrap();
    assert!(handle_s1ap_message(&ctx, enb, &splice(&base, 9999, REJECT)).is_empty());
}

#[test]
fn through_the_handler_a_failure_for_an_unknown_ue_still_gets_an_error_indication() {
    let ctx = MmeContext::new();
    let enb = ctx.enb_add("127.0.0.1:36412".parse().unwrap());
    let bytes = builder::build_initial_context_setup_failure(&InitialContextSetupFailure {
        mme_ue_s1ap_id: 42,
        enb_ue_s1ap_id: 1,
        cause: Cause::RadioNetwork(CauseRadioNetwork::Unspecified),
    })
    .unwrap();
    let out = handle_s1ap_message(&ctx, enb, &bytes);
    assert_eq!(out.len(), 1);
    assert!(matches!(
        decode_s1ap_pdu(&out[0].pdu).unwrap(),
        S1apMessage::ErrorIndication(_)
    ));
}

/// #869 review: a UE-AMBR above 10 Gbit/s is not lost. The legacy Bit Rate is
/// at its maximum and the Rel-15 Extended UE-AMBR (id 259 DL / 260 UL,
/// criticality ignore, TS 36.413 §9.2.1.20) carries the value, for that
/// direction only. The encode runs the criticality oracle under test, so a wrong
/// criticality on the extension fails here too.
#[test]
fn a_ue_ambr_above_10_gbits_travels_in_the_extended_ie() {
    use nextgcore_s1ap_gen::generated as g;
    let mut req = golden_request();
    req.ue_ambr = UeAmbr {
        dl: 15_000_000_000,
        ul: 2_000,
    };
    let bytes = build_initial_context_setup_request(&req).unwrap();
    let pdu = nextgcore_s1ap_gen::decode(&bytes).unwrap();
    let g::S1AP_PDU::InitiatingMessage(m) = pdu else {
        panic!("an initiating message")
    };
    let g::InitiatingMessageValue::Id_InitialContextSetup(r) = m.value else {
        panic!("an Initial Context Setup Request")
    };
    let a = r
        .protocol_i_es
        .0
        .iter()
        .find_map(|ie| match &ie.value {
            g::InitialContextSetupRequestProtocolIEs_EntryValue::Id_uEaggregateMaximumBitrate(
                a,
            ) => Some(a.clone()),
            _ => None,
        })
        .expect("the UE-AMBR IE");
    assert_eq!(a.u_eaggregate_maximum_bit_rate_dl.0, 10_000_000_000);
    assert_eq!(a.u_eaggregate_maximum_bit_rate_ul.0, 2_000);
    let ext = a.ie_extensions.expect("the extension container").0;
    assert_eq!(ext.len(), 1, "DL only");
    assert_eq!(ext[0].id.0, 259);
    assert_eq!(ext[0].criticality.0, g::Criticality::IGNORE);
    assert!(matches!(
        ext[0].extension_value,
        g::UEAggregateMaximumBitrateIE_Extensions_EntryExtensionValue::Id_extended_uEaggregateMaximumBitRateDL(
            g::ExtendedBitRate(15_000_000_000)
        )
    ));
}
