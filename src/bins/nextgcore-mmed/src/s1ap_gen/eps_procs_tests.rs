//! #584: E-RAB Release Indication, E-RAB Modification Indication, Location
//! Reporting, Path Switch with absent `ignore` IEs, and the EPS→5GS handover
//! with the MME as source.
//!
//! Every S1AP message the eNB sends is built here with the generated codec, so
//! the IE set (in particular the IEs a test leaves out) is exactly what the
//! test says, and each one is driven through `handle_s1ap_message`.

use super::*;
use crate::context::{MmeContext, MmeUe};
use crate::s1ap_handler::handle_s1ap_message;

const PLMN: [u8; 3] = [0x00, 0xF1, 0x10];

fn initiating(procedure_code: u8, criticality: u8, value: g::InitiatingMessageValue) -> Vec<u8> {
    nextgcore_s1ap_gen::encode(&g::S1AP_PDU::InitiatingMessage(g::InitiatingMessage {
        procedure_code: g::ProcedureCode(procedure_code),
        criticality: g::Criticality(criticality),
        value,
    }))
    .unwrap()
}

fn g_tai(tac: u16) -> g::TAI {
    g::TAI {
        plm_nidentity: g::TBCD_STRING(PLMN.to_vec()),
        tac: g::TAC(tac.to_be_bytes().to_vec()),
        ie_extensions: None,
    }
}

fn g_cgi(cell: u32) -> g::EUTRAN_CGI {
    g::EUTRAN_CGI {
        plm_nidentity: g::TBCD_STRING(PLMN.to_vec()),
        cell_id: g::CellIdentity(u32_to_bits(cell, 28)),
        ie_extensions: None,
    }
}

/// A UE on `enb_id` with one PDN connection: default bearer 5 and dedicated
/// bearer 6, each with SGW and PGW endpoints. Returns (enb_ue_id, mme_ue_id,
/// mme_ue_s1ap_id, enb_ue_s1ap_id, [bearer 5 id, bearer 6 id]).
fn ue_with_bearers(ctx: &MmeContext, enb_id: u64) -> (u64, u64, u32, u32, [u64; 2]) {
    let enb_ue_s1ap_id = 100;
    let enb_ue_id = ctx.enb_ue_add(enb_id, enb_ue_s1ap_id);
    let mme_ue_id = ctx.mme_ue_add(enb_ue_id);
    ctx.enb_ue_associate_mme_ue(enb_ue_id, mme_ue_id);
    let mme_ue_s1ap_id = ctx.enb_ue_find_by_id(enb_ue_id).unwrap().mme_ue_s1ap_id;
    let sess_id = ctx.sess_add(mme_ue_id, 1);
    let mut ids = [0u64; 2];
    for (i, ebi) in [5u8, 6].into_iter().enumerate() {
        let id = ctx.bearer_add(sess_id, mme_ue_id);
        let mut pool = ctx.bearer_pool.write().unwrap();
        let b = pool.get_mut(&id).unwrap();
        b.ebi = ebi;
        b.qos.qci = if ebi == 5 { 9 } else { 1 };
        b.sgw_s1u_teid = 0x100 + u32::from(ebi);
        b.sgw_s1u_ip.ipv4 = Some([10, 0, 0, 2]);
        b.enb_s1u_teid = 0x200 + u32::from(ebi);
        b.enb_s1u_ip.ipv4 = Some([10, 0, 0, 3]);
        b.pgw_s5u_teid = 0x300 + u32::from(ebi);
        b.pgw_s5u_ip.ipv4 = Some([10, 0, 0, 4]);
        ids[i] = id;
    }
    {
        let mut pool = ctx.sess_pool.write().unwrap();
        let sess = pool.get_mut(&sess_id).unwrap();
        sess.apn = "internet".to_string();
        sess.bearer_list = ids.to_vec();
        sess.pgw_s5c_teid = 0x4444;
        sess.pgw_s5c_ip.ipv4 = Some([10, 0, 0, 4]);
        sess.ambr.uplink = 2_000_000;
        sess.ambr.downlink = 4_000_000;
        sess.paa.addr = [10, 45, 0, 2];
    }
    {
        let mut pool = ctx.mme_ue_pool.write().unwrap();
        let mme_ue: &mut MmeUe = pool.get_mut(&mme_ue_id).unwrap();
        mme_ue.imsi_bcd = "001010123456789".to_string();
        mme_ue.sess_list = vec![sess_id];
        mme_ue.kasme = [0x11; 32];
        mme_ue.kenb = [0x22; 32];
        mme_ue.ue_network_capability.eea = 0xE0;
        mme_ue.ue_network_capability.eia = 0x60;
        mme_ue.ue_network_capability.length = 2;
        mme_ue.selected_int_algorithm = 2;
        mme_ue.selected_enc_algorithm = 0;
        mme_ue.nas_eps.mme_ksi.ksi = 3;
        mme_ue.tai.tac = 7;
        mme_ue.e_cgi.cell_id = 0x77;
    }
    (enb_ue_id, mme_ue_id, mme_ue_s1ap_id, enb_ue_s1ap_id, ids)
}

fn setup() -> (MmeContext, u64) {
    let ctx = MmeContext::new();
    let enb_id = ctx.enb_add("127.0.0.1:36412".parse().unwrap());
    (ctx, enb_id)
}

fn is_error_indication(pdu: &[u8]) -> bool {
    matches!(
        nextgcore_s1ap_gen::decode(pdu),
        Ok(g::S1AP_PDU::InitiatingMessage(g::InitiatingMessage {
            value: g::InitiatingMessageValue::Id_ErrorIndication(_),
            ..
        }))
    )
}

// ---------------------------------------------------------------------------
// Part 4: Path Switch Request with its `ignore` IEs absent
// ---------------------------------------------------------------------------

fn path_switch_reject_ies_only(enb_ue_s1ap_id: u32, mme_ue_s1ap_id: u32) -> Vec<u8> {
    use g::PathSwitchRequestProtocolIEs_EntryValue as V;
    let ie = |id: u16, value: V| g::PathSwitchRequestProtocolIEs_Entry {
        id: g::ProtocolIE_ID(id),
        criticality: g::Criticality(REJECT),
        value,
    };
    initiating(
        PROC_PATH_SWITCH_REQUEST,
        REJECT,
        g::InitiatingMessageValue::Id_PathSwitchRequest(g::PathSwitchRequest {
            protocol_i_es: g::PathSwitchRequestProtocolIEs(vec![
                ie(
                    ID_ENB_UE_S1AP_ID,
                    V::Id_eNB_UE_S1AP_ID(g::ENB_UE_S1AP_ID(enb_ue_s1ap_id)),
                ),
                ie(
                    ID_ERAB_TO_BE_SWITCHED_DL_LIST,
                    V::Id_E_RABToBeSwitchedDLList(g::E_RABToBeSwitchedDLList(vec![
                        g::E_RABToBeSwitchedDLList_Entry {
                            id: g::ProtocolIE_ID(23),
                            criticality: g::Criticality(REJECT),
                            value:
                                g::E_RABToBeSwitchedDLList_EntryValue::Id_E_RABToBeSwitchedDLItem(
                                    g::E_RABToBeSwitchedDLItem {
                                        e_rab_id: g::E_RAB_ID(5),
                                        transport_layer_address: transport(&[10, 0, 0, 9]),
                                        gtp_teid: gtp_teid(0x9999),
                                        ie_extensions: None,
                                    },
                                ),
                        },
                    ])),
                ),
                ie(
                    ID_SOURCE_MME_UE_S1AP_ID,
                    V::Id_SourceMME_UE_S1AP_ID(g::MME_UE_S1AP_ID(mme_ue_s1ap_id)),
                ),
            ]),
        }),
    )
}

/// Driven against the global context with a real S11 socket and a stand-in
/// Serving GW: since #730 the acknowledge waits for the Modify Bearer Response.
#[test]
fn a_path_switch_request_without_cgi_tai_or_security_capabilities_is_acknowledged() {
    let _guard = crate::gtp_path::lock_s11();
    let sgw = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    sgw.set_read_timeout(Some(std::time::Duration::from_secs(3)))
        .unwrap();
    let _route = crate::gtp_path::route_s11_for_test(
        crate::gtp_path::GtpcServer::open(
            "127.0.0.1:0",
            nextgcore_gtp::v2::xact::Gtp2XactConfig::default(),
            7,
        )
        .unwrap(),
        sgw.local_addr().unwrap(),
    );
    let ctx = crate::context::mme_self();
    let addr = |s: &std::net::UdpSocket| s.local_addr().unwrap();
    let old_sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let new_sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let old_enb = ctx.enb_add(addr(&old_sock));
    let (_, mme_ue_id, mme_ue_s1ap_id, _, ids) = ue_with_bearers(ctx, old_enb);
    let sgw_ue_id = ctx.sgw_ue_add(mme_ue_id);
    ctx.mme_ue_pool
        .write()
        .unwrap()
        .get_mut(&mme_ue_id)
        .unwrap()
        .sgw_ue_id = sgw_ue_id;
    let local_teid = ctx.mme_ue_find_by_id(mme_ue_id).unwrap().mme_s11_teid;
    let new_enb = ctx.enb_add(addr(&new_sock));
    crate::s1ap_path::tap_enb_for_test(new_enb);

    let bytes = path_switch_reject_ies_only(200, mme_ue_s1ap_id);
    assert!(matches!(
        decode_path_switch_request(&bytes),
        Class2Decode::Proceed { ref msg, .. }
            if msg.eutran_cgi.is_none() && msg.tai.is_none() && msg.ue_security_capabilities.is_none()
    ));

    assert!(handle_s1ap_message(ctx, new_enb, &bytes).is_empty());
    let mut buf = [0u8; 4096];
    let (len, from) = sgw.recv_from(&mut buf).expect("the Modify Bearer Request");
    let mut raw = bytes::Bytes::copy_from_slice(&buf[..len]);
    let mbr = nextgcore_gtp::v2::Gtp2Message::decode(&mut raw).unwrap();
    assert_eq!(mbr.header.message_type, 34);
    let mut rsp = nextgcore_gtp::v2::Gtp2Message::new(nextgcore_gtp::v2::Gtp2Header::new(
        35,
        local_teid,
        mbr.header.sequence_number,
    ));
    rsp.add_ie(nextgcore_gtp::v2::Gtp2Ie::from_slice(2, 0, &[16, 0]));
    sgw.send_to(&rsp.encode(), from).unwrap();

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let acknowledged = loop {
        let tapped = crate::s1ap_path::take_tapped_for_test(new_enb);
        if let Some(pdu) = tapped.first() {
            break matches!(
                nextgcore_s1ap_gen::decode(pdu),
                Ok(g::S1AP_PDU::SuccessfulOutcome(g::SuccessfulOutcome {
                    value: g::SuccessfulOutcomeValue::Id_PathSwitchRequest(_),
                    ..
                }))
            );
        }
        assert!(
            std::time::Instant::now() < deadline,
            "no answer to the Path Switch Request"
        );
        std::thread::sleep(std::time::Duration::from_millis(10));
    };
    assert!(acknowledged, "expected PATH SWITCH REQUEST ACKNOWLEDGE");
    // The DL endpoint is switched, the stored location is left as it was.
    let bearer = ctx.bearer_find_by_id(ids[0]).unwrap();
    assert_eq!(bearer.enb_s1u_teid, 0x9999);
    let mme_ue = ctx.mme_ue_find_by_id(mme_ue_id).unwrap();
    assert_eq!(mme_ue.tai.tac, 7);
    assert_eq!(mme_ue.e_cgi.cell_id, 0x77);
    crate::network_detach::delete_pdn_connections_locally(ctx, mme_ue_id);
    ctx.mme_ue_remove(mme_ue_id);
}

// ---------------------------------------------------------------------------
// Part 2: E-RAB Release Indication
// ---------------------------------------------------------------------------

fn erab_release_indication(mme: u32, enb: u32, erabs: &[u8], with_location: bool) -> Vec<u8> {
    use g::E_RABReleaseIndicationProtocolIEs_EntryValue as V;
    let ie = |id: u16, criticality: u8, value: V| g::E_RABReleaseIndicationProtocolIEs_Entry {
        id: g::ProtocolIE_ID(id),
        criticality: g::Criticality(criticality),
        value,
    };
    let mut ies = vec![
        ie(
            ID_MME_UE_S1AP_ID,
            REJECT,
            V::Id_MME_UE_S1AP_ID(g::MME_UE_S1AP_ID(mme)),
        ),
        ie(
            ID_ENB_UE_S1AP_ID,
            REJECT,
            V::Id_eNB_UE_S1AP_ID(g::ENB_UE_S1AP_ID(enb)),
        ),
        ie(
            ID_ERAB_RELEASED_LIST,
            IGNORE,
            V::Id_E_RABReleasedList(erab_list(
                &erabs
                    .iter()
                    .map(|e| nextgcore_s1ap::ErabItem {
                        erab_id: *e,
                        cause: Cause::RadioNetwork(
                            nextgcore_s1ap::CauseRadioNetwork::RadioConnectionWithUeLost,
                        ),
                    })
                    .collect::<Vec<_>>(),
            )),
        ),
    ];
    if with_location {
        ies.push(ie(
            189,
            IGNORE,
            V::Id_UserLocationInformation(g::UserLocationInformation {
                eutran_cgi: g_cgi(0x1234),
                tai: g_tai(9),
                ie_extensions: None,
            }),
        ));
    }
    initiating(
        PROC_E_RAB_RELEASE_INDICATION,
        IGNORE,
        g::InitiatingMessageValue::Id_E_RABReleaseIndication(g::E_RABReleaseIndication {
            protocol_i_es: g::E_RABReleaseIndicationProtocolIEs(ies),
        }),
    )
}

#[test]
fn an_erab_release_indication_releases_the_dedicated_bearer_and_keeps_the_default() {
    let _guard = crate::gtp_path::lock_s11();
    let (ctx, enb_id) = setup();
    let (_, mme_ue_id, mme, enb, ids) = ue_with_bearers(&ctx, enb_id);

    let bytes = erab_release_indication(mme, enb, &[6, 5], true);
    let Class2Decode::Proceed { msg, notify } = decode_erab_release_indication(&bytes) else {
        panic!("decode");
    };
    assert!(notify.is_empty());
    assert_eq!(
        msg.released.iter().map(|r| r.erab_id).collect::<Vec<_>>(),
        vec![6, 5]
    );

    // Nothing is answered on S1 (Class 2, no unknown IE).
    assert!(handle_s1ap_message(&ctx, enb_id, &bytes).is_empty());
    let dedicated = ctx.bearer_find_by_id(ids[1]).unwrap();
    assert!(dedicated.released_by_enb, "bearer 6 is released by the eNB");
    assert_eq!(dedicated.enb_s1u_teid, 0, "its eNB endpoint is gone");
    let default = ctx.bearer_find_by_id(ids[0]).unwrap();
    assert!(
        !default.released_by_enb,
        "the default bearer is not released this way"
    );
    // The User Location Information was stored.
    let mme_ue = ctx.mme_ue_find_by_id(mme_ue_id).unwrap();
    assert_eq!(mme_ue.tai.tac, 9);
    assert_eq!(mme_ue.e_cgi.cell_id, 0x1234);

    // The handler commands the Serving GW for bearer 6 only (TS 23.401 §5.4.4.2 step 2).
    assert_eq!(
        crate::s1ap_handler::handle_erab_release_indication(&ctx, enb_id, &msg).1,
        vec![6]
    );

    // The Delete Bearer Request that follows deletes it with no NAS (steps 6-8);
    // the default bearer named alongside is not touched.
    let teid = ctx.mme_ue_find_by_id(mme_ue_id).unwrap().mme_s11_teid;
    let (_, deleted) =
        crate::s11_handler::delete_enb_released_bearers(&ctx, teid, &[6, 5]).expect("deleted");
    assert_eq!(deleted, vec![6]);
    assert!(ctx.bearer_find_by_id(ids[1]).is_none());
    assert!(ctx.bearer_find_by_id(ids[0]).is_some());
    let sess_id = ctx.mme_ue_find_by_id(mme_ue_id).unwrap().sess_list[0];
    assert_eq!(
        ctx.sess_find_by_id(sess_id).unwrap().bearer_list,
        vec![ids[0]]
    );
    // A second request for the same bearer finds nothing to delete.
    assert!(crate::s11_handler::delete_enb_released_bearers(&ctx, teid, &[6]).is_none());
}

#[test]
fn the_delete_bearer_command_carries_each_ebi_and_the_uli() {
    use nextgcore_gtp::v2::{Gtp2BearerContextIe, Gtp2IeType};
    let mme_ue = MmeUe::default();
    let sgw_ue = crate::context::SgwUe {
        sgw_s11_teid: 0xabcd,
        ..Default::default()
    };
    let msg =
        crate::s11_build::build_delete_bearer_command(&mme_ue, &sgw_ue, &[6, 7], 0x22).unwrap();
    assert_eq!(
        msg.header.message_type, 66,
        "Delete Bearer Command (TS 29.274 Table 6.1-1)"
    );
    assert_eq!(msg.header.teid, Some(0xabcd));
    let ebis: Vec<u8> = msg
        .get_ies(Gtp2IeType::BearerContext as u8)
        .into_iter()
        .map(|ie| {
            Gtp2BearerContextIe::decode(&ie.value)
                .unwrap()
                .ebi()
                .unwrap()
        })
        .collect();
    assert_eq!(ebis, vec![6, 7]);
    assert!(msg.get_ie(Gtp2IeType::Uli as u8, 0).is_some());
    assert!(crate::s11_build::build_delete_bearer_command(&mme_ue, &sgw_ue, &[], 1).is_err());
}

#[test]
fn an_erab_release_indication_for_an_unknown_ue_gets_an_error_indication() {
    let (ctx, enb_id) = setup();
    let out = handle_s1ap_message(&ctx, enb_id, &erab_release_indication(999, 1, &[6], false));
    assert_eq!(out.len(), 1);
    assert!(is_error_indication(&out[0].pdu));
}

// ---------------------------------------------------------------------------
// Part 2: E-RAB Modification Indication
// ---------------------------------------------------------------------------

fn erab_modification_indication(mme: u32, enb: u32, erabs: Option<&[(u8, u32)]>) -> Vec<u8> {
    use g::E_RABModificationIndicationProtocolIEs_EntryValue as V;
    let ie = |id: u16, value: V| g::E_RABModificationIndicationProtocolIEs_Entry {
        id: g::ProtocolIE_ID(id),
        criticality: g::Criticality(REJECT),
        value,
    };
    let mut ies = vec![
        ie(
            ID_MME_UE_S1AP_ID,
            V::Id_MME_UE_S1AP_ID(g::MME_UE_S1AP_ID(mme)),
        ),
        ie(
            ID_ENB_UE_S1AP_ID,
            V::Id_eNB_UE_S1AP_ID(g::ENB_UE_S1AP_ID(enb)),
        ),
    ];
    if let Some(erabs) = erabs {
        ies.push(ie(
            ID_ERAB_TO_BE_MODIFIED_LIST_BEARER_MOD_IND,
            V::Id_E_RABToBeModifiedListBearerModInd(g::E_RABToBeModifiedListBearerModInd(
                erabs
                    .iter()
                    .map(|(erab, teid)| g::E_RABToBeModifiedListBearerModInd_Entry {
                        id: g::ProtocolIE_ID(200),
                        criticality: g::Criticality(REJECT),
                        value: g::E_RABToBeModifiedListBearerModInd_EntryValue::Id_E_RABToBeModifiedItemBearerModInd(
                            g::E_RABToBeModifiedItemBearerModInd {
                                e_rab_id: g::E_RAB_ID(*erab),
                                transport_layer_address: transport(&[10, 9, 9, 9]),
                                dl_gtp_teid: gtp_teid(*teid),
                                ie_extensions: None,
                            },
                        ),
                    })
                    .collect(),
            )),
        ));
    }
    initiating(
        PROC_E_RAB_MODIFICATION_INDICATION,
        REJECT,
        g::InitiatingMessageValue::Id_E_RABModificationIndication(g::E_RABModificationIndication {
            protocol_i_es: g::E_RABModificationIndicationProtocolIEs(ies),
        }),
    )
}

/// (modified, failed (id, cause)) of an E-RAB MODIFICATION CONFIRM.
fn confirm_lists(pdu: &[u8]) -> (Vec<u8>, Vec<(u8, g::Cause)>) {
    let Ok(g::S1AP_PDU::SuccessfulOutcome(g::SuccessfulOutcome {
        value: g::SuccessfulOutcomeValue::Id_E_RABModificationIndication(c),
        ..
    })) = nextgcore_s1ap_gen::decode(pdu)
    else {
        panic!("expected E-RAB MODIFICATION CONFIRM");
    };
    let (mut modified, mut failed) = (Vec::new(), Vec::new());
    use g::E_RABModificationConfirmProtocolIEs_EntryValue as V;
    for ie in c.protocol_i_es.0 {
        match ie.value {
            V::Id_E_RABModifyListBearerModConf(l) => {
                for e in l.0 {
                    let g::E_RABModifyListBearerModConf_EntryValue::Id_E_RABModifyItemBearerModConf(
                        i,
                    ) = e.value;
                    modified.push(i.e_rab_id.0);
                }
            }
            V::Id_E_RABFailedToModifyListBearerModConf(l) => {
                for e in l.0 {
                    let g::E_RABList_EntryValue::Id_E_RABItem(i) = e.value;
                    failed.push((i.e_rab_id.0, i.cause));
                }
            }
            _ => {}
        }
    }
    (modified, failed)
}

#[test]
fn an_erab_modification_indication_switches_known_erabs_and_fails_unknown_ones() {
    let _guard = crate::gtp_path::lock_s11();
    let (ctx, enb_id) = setup();
    let (_, _, mme, enb, ids) = ue_with_bearers(&ctx, enb_id);
    let bytes = erab_modification_indication(mme, enb, Some(&[(5, 0x5151), (9, 0x9191)]));

    // This unit context has no Serving GW path, so the Modify Bearer Request
    // cannot go and the confirm says the core did not switch E-RAB 5.
    let out = handle_s1ap_message(&ctx, enb_id, &bytes);
    assert_eq!(out.len(), 1);
    let (modified, failed) = confirm_lists(&out[0].pdu);
    assert!(modified.is_empty());
    assert_eq!(failed.len(), 2);
    assert!(failed.contains(&(9, g::Cause::RadioNetwork(g::CauseRadioNetwork(30)))));
    assert!(failed
        .iter()
        .any(|(e, c)| *e == 5 && matches!(c, g::Cause::Transport(_))));
    // The new downlink endpoint is stored for the Modify Bearer Request.
    assert_eq!(ctx.bearer_find_by_id(ids[0]).unwrap().enb_s1u_teid, 0x5151);

    // With the Serving GW's answer: accepted, E-RAB 5 is modified ...
    let pending = crate::gtp_path::PendingErabModification {
        enb_id,
        confirm: crate::s1ap_gen::ErabModificationConfirm {
            mme_ue_s1ap_id: mme,
            enb_ue_s1ap_id: enb,
            modified: vec![5],
            failed: vec![],
            to_be_released: vec![],
        },
        notify: vec![],
    };
    let send = crate::s1ap_handler::erab_modification_confirm(pending.clone(), 16).unwrap();
    assert_eq!(send.enb_id, enb_id);
    assert_eq!(confirm_lists(&send.pdu), (vec![5], vec![]));
    // ... refused, it failed.
    let send = crate::s1ap_handler::erab_modification_confirm(pending.clone(), 64).unwrap();
    let (modified, failed) = confirm_lists(&send.pdu);
    assert!(modified.is_empty());
    assert_eq!(failed.iter().map(|f| f.0).collect::<Vec<_>>(), vec![5]);

    // The S11 response path takes the parked record by sequence number.
    crate::gtp_path::record_pending_erab_modification_for_test(0x5_84, pending);
    assert!(crate::gtp_path::take_pending_erab_modification(0x5_84).is_some());
    assert!(crate::gtp_path::take_pending_erab_modification(0x5_84).is_none());
}

#[test]
fn an_erab_modification_indication_without_its_list_gets_an_error_indication() {
    let (ctx, enb_id) = setup();
    let (_, _, mme, enb, _) = ue_with_bearers(&ctx, enb_id);
    let out = handle_s1ap_message(&ctx, enb_id, &erab_modification_indication(mme, enb, None));
    assert_eq!(out.len(), 1);
    assert!(is_error_indication(&out[0].pdu));
}

// ---------------------------------------------------------------------------
// Part 3: Location Reporting
// ---------------------------------------------------------------------------

fn location_report(mme: u32, enb: u32) -> Vec<u8> {
    use g::LocationReportProtocolIEs_EntryValue as V;
    let ie = |id: u16, criticality: u8, value: V| g::LocationReportProtocolIEs_Entry {
        id: g::ProtocolIE_ID(id),
        criticality: g::Criticality(criticality),
        value,
    };
    initiating(
        PROC_LOCATION_REPORT,
        IGNORE,
        g::InitiatingMessageValue::Id_LocationReport(g::LocationReport {
            protocol_i_es: g::LocationReportProtocolIEs(vec![
                ie(
                    ID_MME_UE_S1AP_ID,
                    REJECT,
                    V::Id_MME_UE_S1AP_ID(g::MME_UE_S1AP_ID(mme)),
                ),
                ie(
                    ID_ENB_UE_S1AP_ID,
                    REJECT,
                    V::Id_eNB_UE_S1AP_ID(g::ENB_UE_S1AP_ID(enb)),
                ),
                ie(ID_EUTRAN_CGI, IGNORE, V::Id_EUTRAN_CGI(g_cgi(0xABCDE))),
                ie(ID_TAI, IGNORE, V::Id_TAI(g_tai(0x0102))),
                ie(
                    ID_REQUEST_TYPE,
                    IGNORE,
                    V::Id_RequestType(g::RequestType {
                        event_type: g::EventType(g::EventType::CHANGE_OF_SERVE_CELL),
                        report_area: g::ReportArea(g::ReportArea::ECGI),
                        ie_extensions: None,
                    }),
                ),
            ]),
        }),
    )
}

fn location_reporting_failure(mme: u32, enb: u32) -> Vec<u8> {
    use g::LocationReportingFailureIndicationProtocolIEs_EntryValue as V;
    let ie = |id: u16, criticality: u8, value: V| {
        g::LocationReportingFailureIndicationProtocolIEs_Entry {
            id: g::ProtocolIE_ID(id),
            criticality: g::Criticality(criticality),
            value,
        }
    };
    initiating(
        PROC_LOCATION_REPORTING_FAILURE_INDICATION,
        IGNORE,
        g::InitiatingMessageValue::Id_LocationReportingFailureIndication(
            g::LocationReportingFailureIndication {
                protocol_i_es: g::LocationReportingFailureIndicationProtocolIEs(vec![
                    ie(
                        ID_MME_UE_S1AP_ID,
                        REJECT,
                        V::Id_MME_UE_S1AP_ID(g::MME_UE_S1AP_ID(mme)),
                    ),
                    ie(
                        ID_ENB_UE_S1AP_ID,
                        REJECT,
                        V::Id_eNB_UE_S1AP_ID(g::ENB_UE_S1AP_ID(enb)),
                    ),
                    ie(
                        ID_CAUSE,
                        IGNORE,
                        V::Id_Cause(g::Cause::RadioNetwork(g::CauseRadioNetwork(0))),
                    ),
                ]),
            },
        ),
    )
}

#[test]
fn a_location_report_becomes_the_stored_location() {
    let (ctx, enb_id) = setup();
    let (enb_ue_id, mme_ue_id, mme, enb, _) = ue_with_bearers(&ctx, enb_id);
    assert!(handle_s1ap_message(&ctx, enb_id, &location_report(mme, enb)).is_empty());
    let mme_ue = ctx.mme_ue_find_by_id(mme_ue_id).unwrap();
    assert_eq!(mme_ue.tai.tac, 0x0102);
    assert_eq!(mme_ue.e_cgi.cell_id, 0xABCDE);
    assert_eq!(
        ctx.enb_ue_find_by_id(enb_ue_id).unwrap().saved.tai.tac,
        0x0102
    );
    // An unknown pair gets ERROR INDICATION.
    let out = handle_s1ap_message(&ctx, enb_id, &location_report(mme, enb + 1));
    assert!(out.len() == 1 && is_error_indication(&out[0].pdu));
}

#[test]
fn the_pgw_change_reporting_action_drives_location_reporting_control() {
    let (ctx, enb_id) = setup();
    let (_, mme_ue_id, mme, enb, _) = ue_with_bearers(&ctx, enb_id);
    let event_of = |pdu: &[u8]| {
        let Ok(g::S1AP_PDU::InitiatingMessage(g::InitiatingMessage {
            value: g::InitiatingMessageValue::Id_LocationReportingControl(m),
            ..
        })) = nextgcore_s1ap_gen::decode(pdu)
        else {
            panic!("expected LOCATION REPORTING CONTROL");
        };
        let mut ids = (None, None, None);
        for ie in m.protocol_i_es.0 {
            use g::LocationReportingControlProtocolIEs_EntryValue as V;
            match ie.value {
                V::Id_MME_UE_S1AP_ID(v) => ids.0 = Some(v.0),
                V::Id_eNB_UE_S1AP_ID(v) => ids.1 = Some(v.0),
                V::Id_RequestType(r) => {
                    assert_eq!(r.report_area.0, g::ReportArea::ECGI);
                    ids.2 = Some(r.event_type.0);
                }
            }
        }
        ids
    };
    // "Stop Reporting" with nothing active, or a TAI-only action, sends nothing.
    assert!(crate::s11_handler::location_reporting_for_action(&ctx, mme_ue_id, Some(0)).is_none());
    assert!(crate::s11_handler::location_reporting_for_action(&ctx, mme_ue_id, Some(3)).is_none());
    assert!(crate::s11_handler::location_reporting_for_action(&ctx, mme_ue_id, None).is_none());
    // "Start Reporting ECGI" (4) starts change-of-serve-cell reporting.
    let start =
        crate::s11_handler::location_reporting_for_action(&ctx, mme_ue_id, Some(4)).unwrap();
    assert_eq!(start.enb_id, enb_id);
    assert_eq!(
        event_of(&start.pdu),
        (
            Some(mme),
            Some(enb),
            Some(g::EventType::CHANGE_OF_SERVE_CELL)
        )
    );
    assert!(
        ctx.mme_ue_find_by_id(mme_ue_id)
            .unwrap()
            .location_reporting_active
    );
    // A failure indication from the eNB ends it ...
    assert!(handle_s1ap_message(&ctx, enb_id, &location_reporting_failure(mme, enb)).is_empty());
    assert!(
        !ctx.mme_ue_find_by_id(mme_ue_id)
            .unwrap()
            .location_reporting_active
    );
    // ... and "Stop Reporting" after a restart (6 = TAI and ECGI) stops it.
    crate::s11_handler::location_reporting_for_action(&ctx, mme_ue_id, Some(6)).unwrap();
    let stop = crate::s11_handler::location_reporting_for_action(&ctx, mme_ue_id, Some(0)).unwrap();
    assert_eq!(
        event_of(&stop.pdu).2,
        Some(g::EventType::STOP_CHANGE_OF_SERVE_CELL)
    );
    // A LOCATION REPORTING CONTROL from an eNB is a message only the MME sends.
    assert_eq!(
        classify_unmatched(&start.pdu),
        Unmatched::MmeOriginated {
            procedure_code: PROC_LOCATION_REPORTING_CONTROL
        }
    );
}

// ---------------------------------------------------------------------------
// Part 1: EPS→5GS handover, the MME as source
// ---------------------------------------------------------------------------

const GNB_ID: u32 = 0x00_1234;
const S2T: &[u8] = &[0xA1, 0xB2, 0xC3, 0xD4];
const T2S: &[u8] = &[0x7E, 0x57, 0x00, 0x01];

fn handover_required_to_gnb(mme: u32, enb: u32, handover_type: u8) -> Vec<u8> {
    use g::HandoverRequiredProtocolIEs_EntryValue as V;
    let ie = |id: u16, criticality: u8, value: V| g::HandoverRequiredProtocolIEs_Entry {
        id: g::ProtocolIE_ID(id),
        criticality: g::Criticality(criticality),
        value,
    };
    let target = g::TargetID::TargetgNgRanNode_ID(g::TargetNgRanNode_ID {
        global_ran_node_id: g::Global_RAN_NODE_ID::GNB(g::GNB {
            global_g_nb_id: g::Global_GNB_ID {
                plmn_identity: g::TBCD_STRING(PLMN.to_vec()),
                gnb_id: g::GNB_Identity::GNB_ID(g::GNB_ID(u32_to_bits(GNB_ID, 24))),
                ie_extensions: None,
            },
            ie_extensions: None,
        }),
        selected_tai: g::FiveGSTAI {
            plm_nidentity: g::TBCD_STRING(PLMN.to_vec()),
            five_gstac: g::FiveGSTAC(vec![0x00, 0x00, 0x01]),
            ie_extensions: None,
        },
        ie_extensions: None,
    });
    initiating(
        PROC_HANDOVER_PREPARATION,
        REJECT,
        g::InitiatingMessageValue::Id_HandoverPreparation(g::HandoverRequired {
            protocol_i_es: g::HandoverRequiredProtocolIEs(vec![
                ie(
                    ID_MME_UE_S1AP_ID,
                    REJECT,
                    V::Id_MME_UE_S1AP_ID(g::MME_UE_S1AP_ID(mme)),
                ),
                ie(
                    ID_ENB_UE_S1AP_ID,
                    REJECT,
                    V::Id_eNB_UE_S1AP_ID(g::ENB_UE_S1AP_ID(enb)),
                ),
                ie(
                    ID_HANDOVER_TYPE,
                    REJECT,
                    V::Id_HandoverType(g::HandoverType(handover_type)),
                ),
                ie(
                    ID_CAUSE,
                    IGNORE,
                    V::Id_Cause(g::Cause::RadioNetwork(g::CauseRadioNetwork(16))),
                ),
                ie(ID_TARGET_ID, REJECT, V::Id_TargetID(target)),
                ie(
                    ID_SOURCE_TO_TARGET_CONTAINER,
                    REJECT,
                    V::Id_Source_ToTarget_TransparentContainer(
                        g::Source_ToTarget_TransparentContainer(S2T.to_vec()),
                    ),
                ),
            ]),
        }),
    )
}

/// The Cause of a HANDOVER PREPARATION FAILURE, if `pdu` is one.
fn preparation_failure_cause(pdu: &[u8]) -> Option<g::Cause> {
    let Ok(g::S1AP_PDU::UnsuccessfulOutcome(g::UnsuccessfulOutcome {
        value: g::UnsuccessfulOutcomeValue::Id_HandoverPreparation(f),
        ..
    })) = nextgcore_s1ap_gen::decode(pdu)
    else {
        return None;
    };
    f.protocol_i_es.0.into_iter().find_map(|ie| match ie.value {
        g::HandoverPreparationFailureProtocolIEs_EntryValue::Id_Cause(c) => Some(c),
        _ => None,
    })
}

#[test]
fn a_handover_required_to_a_gnb_decodes_its_target() {
    let bytes = handover_required_to_gnb(1, 2, g::HandoverType::EPS_TO_5GS);
    let HandoverRequiredDecode::ToFivegs { msg, notify } = decode_handover_required(&bytes) else {
        panic!("a gNB target is an EPS to 5GS handover");
    };
    assert!(notify.is_empty());
    assert_eq!(
        msg.target,
        crate::n26_build::GnbTarget {
            plmn: PLMN,
            gnb_id: GNB_ID,
            gnb_id_len: 24,
            tac: [0, 0, 1],
        }
    );
    assert_eq!(msg.source_to_target_container, S2T);
    assert_eq!(msg.handover_type, nextgcore_s1ap::HandoverType::EpsTo5gs);
}

#[test]
fn with_n26_off_a_handover_to_5gs_fails_with_unknown_target() {
    let _guard = crate::gtp_path::lock_s11();
    crate::n26_path::set_for_test(false);
    let (ctx, enb_id) = setup();
    let (_, _, mme, enb, _) = ue_with_bearers(&ctx, enb_id);
    let out = handle_s1ap_message(
        &ctx,
        enb_id,
        &handover_required_to_gnb(mme, enb, g::HandoverType::EPS_TO_5GS),
    );
    assert_eq!(out.len(), 1);
    assert_eq!(
        preparation_failure_cause(&out[0].pdu),
        Some(g::Cause::RadioNetwork(g::CauseRadioNetwork(
            g::CauseRadioNetwork::UNKNOWN_TARGET_ID
        )))
    );
}

/// The next Forward Relocation Request the stand-in AMF receives that is not a
/// T3 retransmission of one it already saw.
fn recv_fresh(sock: &std::net::UdpSocket, seen: &mut Vec<u32>) -> nextgcore_gtp::v2::Gtp2Message {
    let mut buf = [0u8; 4096];
    loop {
        let (len, _) = sock
            .recv_from(&mut buf)
            .expect("the AMF receives the request");
        let msg =
            nextgcore_gtp::v2::Gtp2Message::decode(&mut bytes::Bytes::copy_from_slice(&buf[..len]))
                .unwrap();
        if !seen.contains(&msg.header.sequence_number) {
            seen.push(msg.header.sequence_number);
            return msg;
        }
    }
}

/// The whole source-side procedure against amfd's REAL N26 code (the strict
/// peer): mmed's Forward Relocation Request leaves mmed's real N26 socket and
/// is parsed by amfd's EPS→5GS parser and security mapping; amfd's real
/// builders produce the Forward Relocation Response and the Complete
/// Notification mmed then acts on.
#[test]
fn an_eps_to_5gs_handover_runs_against_the_amfs_own_n26_codec() {
    use nextgcore_amfd::n26_eps_to_5gs as amf;
    use nextgcore_gtp::v2::Gtp2FTeidIe;

    let _guard = crate::gtp_path::lock_s11();
    crate::n26_path::clear_eps_to_5gs_relocations_for_test();

    let amf_sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    amf_sock
        .set_read_timeout(Some(std::time::Duration::from_secs(3)))
        .unwrap();
    let server = crate::n26_path::N26Server::open(
        "127.0.0.1:0".parse().unwrap(),
        nextgcore_gtp::v2::xact::Gtp2XactConfig::default(),
        3,
    )
    .unwrap();
    assert!(
        crate::n26_path::install_server(server),
        "this is the only test that installs the N26 server"
    );
    crate::n26_path::set_for_test(true);

    let (mut ctx, enb_id) = setup();
    ctx.amf_n26_list = vec![amf_sock.local_addr().unwrap()];
    let (enb_ue_id, mme_ue_id, mme, enb, _) = ue_with_bearers(&ctx, enb_id);

    // A Handover Type that is not eps-to-5gs is refused before N26.
    let out = handle_s1ap_message(
        &ctx,
        enb_id,
        &handover_required_to_gnb(mme, enb, g::HandoverType::INTRALTE),
    );
    assert!(out.len() == 1 && preparation_failure_cause(&out[0].pdu).is_some());

    // --- Step 1-3: HANDOVER REQUIRED -> Forward Relocation Request -------------
    let out = handle_s1ap_message(
        &ctx,
        enb_id,
        &handover_required_to_gnb(mme, enb, g::HandoverType::EPS_TO_5GS),
    );
    assert!(
        out.is_empty(),
        "nothing goes to the eNB before the AMF answers: {out:?}"
    );

    let mut seen = Vec::new();
    let frr = recv_fresh(&amf_sock, &mut seen);
    let parsed = amf::parse_eps_to_5gs_forward_relocation_request(&frr)
        .expect("amfd's EPS to 5GS parser accepts mmed's Forward Relocation Request");
    assert_eq!(parsed.imsi.as_deref(), Some("001010123456789"));
    assert_eq!(
        parsed.mme_fteid.interface_type,
        crate::n26_build::S10_N26_MME_GTP_C
    );
    assert_eq!(parsed.source_to_target_container, S2T);
    assert_eq!(parsed.target.gnb_id, GNB_ID);
    assert_eq!(parsed.target.gnb_id_len, 24);
    assert_eq!(parsed.target.tac, 1);
    assert_eq!(parsed.target.plmn_bcd, PLMN);
    assert!(!parsed.direct_forwarding);
    assert_eq!(parsed.pdn_connections.len(), 1);
    let pdn = &parsed.pdn_connections[0];
    assert_eq!(pdn.apn, "internet");
    assert_eq!(pdn.linked_ebi, 5);
    assert_eq!(pdn.bearer_ebis, vec![5, 6]);
    assert_eq!(pdn.pgw_c_fteid.as_ref().map(|f| f.teid), Some(0x4444));
    assert_eq!(pdn.apn_ambr_kbps, Some((2_000, 4_000)));
    // The EPS security context: K_ASME, eKSI, NAS algorithms and the fresh
    // {NH, NCC} pair (NCC 0 -> 1, NH from K_eNB, TS 33.401 Annex A.4).
    let sec = &parsed.security;
    assert_eq!(sec.kasme, [0x11; 32]);
    assert_eq!(sec.ksi_asme, 3);
    assert_eq!(sec.used_nas_integrity_algorithm, 2);
    assert_eq!(sec.ncc, 1);
    assert_eq!(
        sec.nh,
        Some(nextgcore_crypt::kdf::nextgcore_kdf_nh_enb(
            &[0x11; 32],
            &[0x22; 32]
        ))
    );
    assert_eq!(sec.ue_network_capability, vec![0xE0, 0x60]);
    amf::map_eps_security_context(sec, None, 0xFF, 0xFF, |_, _, _, _| [0; 4])
        .expect("amfd can map mmed's EPS security context to a 5G one");
    assert_eq!(
        crate::n26_path::eps_to_5gs_relocation(mme_ue_id).map(|r| r.source_enb_ue_id),
        Some(enb_ue_id)
    );

    // --- Step 14: an accepted Forward Relocation Response -> HANDOVER COMMAND --
    let amf_fteid = Gtp2FTeidIe::new_ipv4(amf::N26_AMF_GTP_C, 0xA3F0, [127, 0, 0, 1]);
    let rsp = amf::build_eps_to_5gs_forward_relocation_response(
        frr.header.sequence_number,
        parsed.mme_fteid.teid,
        &amf_fteid,
        &[amf::bearer_context_for_ebi(5)],
        T2S,
    );
    let out = crate::n26_path::handle_eps_to_5gs_relocation_response(&ctx, &rsp);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].enb_id, enb_id);
    let Ok(g::S1AP_PDU::SuccessfulOutcome(g::SuccessfulOutcome {
        value: g::SuccessfulOutcomeValue::Id_HandoverPreparation(cmd),
        ..
    })) = nextgcore_s1ap_gen::decode(&out[0].pdu)
    else {
        panic!("expected HANDOVER COMMAND");
    };
    let (mut ho_type, mut container, mut released) = (None, None, Vec::new());
    for ie in cmd.protocol_i_es.0 {
        use g::HandoverCommandProtocolIEs_EntryValue as V;
        match ie.value {
            V::Id_HandoverType(t) => ho_type = Some(t.0),
            V::Id_Target_ToSource_TransparentContainer(c) => container = Some(c.0),
            V::Id_E_RABtoReleaseListHOCmd(l) => {
                for e in l.0 {
                    let g::E_RABList_EntryValue::Id_E_RABItem(i) = e.value;
                    released.push(i.e_rab_id.0);
                }
            }
            _ => {}
        }
    }
    assert_eq!(ho_type, Some(g::HandoverType::EPS_TO_5GS));
    assert_eq!(
        container.as_deref(),
        Some(T2S),
        "the NG-RAN container, verbatim"
    );
    assert_eq!(
        released,
        vec![6],
        "the bearer the AMF did not set up is released"
    );
    // A duplicate of the response drives nothing (its record moved on).
    let late = amf::build_eps_to_5gs_forward_relocation_response(
        frr.header.sequence_number + 1,
        parsed.mme_fteid.teid,
        &amf_fteid,
        &[],
        T2S,
    );
    assert!(crate::n26_path::handle_eps_to_5gs_relocation_response(&ctx, &late).is_empty());

    // --- Execution steps 5-6, 13: Complete Notification -> Ack + release ------
    let notification =
        amf::build_forward_relocation_complete_notification(77, parsed.mme_fteid.teid);
    let (ack, release) = crate::n26_path::complete_eps_to_5gs_relocation(&ctx, &notification)
        .expect("the notification completes the relocation");
    assert_eq!(ack.header.message_type, 136);
    assert_eq!(ack.header.teid, Some(0xA3F0), "addressed to the AMF's TEID");
    assert_eq!(ack.header.sequence_number, 77);
    assert_eq!(
        ack.get_ie(nextgcore_gtp::v2::Gtp2IeType::Cause as u8, 0)
            .and_then(|c| c.value.first().copied()),
        Some(16)
    );
    assert_eq!(release.len(), 1);
    assert_eq!(release[0].enb_id, enb_id);
    let Ok(g::S1AP_PDU::InitiatingMessage(g::InitiatingMessage {
        value: g::InitiatingMessageValue::Id_UEContextRelease(_),
        ..
    })) = nextgcore_s1ap_gen::decode(&release[0].pdu)
    else {
        panic!("expected UE CONTEXT RELEASE COMMAND");
    };
    assert!(
        ctx.mme_ue_find_by_id(mme_ue_id).is_none(),
        "the AMF serves the UE now"
    );
    assert!(crate::n26_path::complete_eps_to_5gs_relocation(&ctx, &notification).is_none());

    // --- A refusing AMF: HANDOVER PREPARATION FAILURE --------------------------
    let (_, mme_ue_id, mme, enb, _) = ue_with_bearers(&ctx, enb_id);
    assert!(handle_s1ap_message(
        &ctx,
        enb_id,
        &handover_required_to_gnb(mme, enb, g::HandoverType::EPS_TO_5GS)
    )
    .is_empty());
    let frr = recv_fresh(&amf_sock, &mut seen);
    let refusal = amf::build_forward_relocation_response_refusal(
        frr.header.sequence_number,
        crate::n26_path::eps_to_5gs_local_teid(mme_ue_id),
        amf::CAUSE_RELOCATION_FAILURE,
    );
    let out = crate::n26_path::handle_eps_to_5gs_relocation_response(&ctx, &refusal);
    assert_eq!(out.len(), 1);
    assert_eq!(
        preparation_failure_cause(&out[0].pdu),
        Some(g::Cause::RadioNetwork(g::CauseRadioNetwork(
            g::CauseRadioNetwork::HO_FAILURE_IN_TARGET_EPC_E_NB_OR_TARGET_SYSTEM
        )))
    );
    assert!(crate::n26_path::eps_to_5gs_relocation(mme_ue_id).is_none());

    // --- HANDOVER CANCEL abandons the relocation -------------------------------
    assert!(handle_s1ap_message(
        &ctx,
        enb_id,
        &handover_required_to_gnb(mme, enb, g::HandoverType::EPS_TO_5GS)
    )
    .is_empty());
    let frr = recv_fresh(&amf_sock, &mut seen);
    assert!(crate::n26_path::eps_to_5gs_relocation(mme_ue_id).is_some());
    let cancel = crate::s1ap_handler::handle_handover_cancel(
        &ctx,
        enb_id,
        &nextgcore_s1ap::HandoverCancel {
            mme_ue_s1ap_id: mme,
            enb_ue_s1ap_id: enb,
            cause: Cause::RadioNetwork(nextgcore_s1ap::CauseRadioNetwork::HandoverCancelled),
        },
    );
    assert_eq!(cancel.len(), 1, "HANDOVER CANCEL ACKNOWLEDGE");
    assert!(crate::n26_path::eps_to_5gs_relocation(mme_ue_id).is_none());
    let late = amf::build_eps_to_5gs_forward_relocation_response(
        frr.header.sequence_number,
        crate::n26_path::eps_to_5gs_local_teid(mme_ue_id),
        &amf_fteid,
        &[],
        T2S,
    );
    assert!(
        crate::n26_path::handle_eps_to_5gs_relocation_response(&ctx, &late).is_empty(),
        "a cancelled handover gets no HANDOVER COMMAND"
    );

    // #592: and the AMF is told (TS 23.502 §4.11.1.2.3 step 2). amfd's own parser
    // reads the Relocation Cancel Request; the AMF had not answered, so mmed has no
    // AMF TEID and the header TEID is 0 (TS 29.274 §5.5.2).
    let rcr = recv_fresh(&amf_sock, &mut seen);
    assert_eq!(rcr.header.message_type, 139, "Relocation Cancel Request");
    let parsed = amf::parse_relocation_cancel_request(&rcr);
    assert_eq!(parsed.imsi.as_deref(), Some("001010123456789"));
    assert_eq!(parsed.amf_teid, 0);
    // amfd's Relocation Cancel Response closes mmed's request.
    let n26 = crate::n26_path::server().expect("installed");
    let before = n26.outstanding();
    amf_sock
        .send_to(
            &amf::build_relocation_cancel_response(
                rcr.header.sequence_number,
                crate::n26_path::eps_to_5gs_local_teid(mme_ue_id),
                16,
            )
            .encode(),
            n26.local_addr(),
        )
        .unwrap();
    for _ in 0..200 {
        if n26.outstanding() < before {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    assert!(
        n26.outstanding() < before,
        "the Relocation Cancel Response closes the request"
    );

    crate::n26_path::set_for_test(false);
}

#[test]
fn the_source_serving_gw_is_released_without_operation_indication_after_eps_to_5gs() {
    use nextgcore_gtp::v2::{Gtp2IeType, Gtp2IndicationIe};
    let oi = |action| {
        let msg = crate::s11_build::build_delete_session_request(
            &crate::context::MmeSess::default(),
            &MmeUe::default(),
            &crate::context::SgwUe::default(),
            5,
            action,
            1,
        )
        .unwrap();
        Gtp2IndicationIe::decode(&msg.get_ie(Gtp2IeType::Indication as u8, 0).unwrap().value)
            .unwrap()
            .oi
    };
    // TS 23.401 §5.5.1.2.2 step 19: "Operation Indication flag is not set" --
    // the SMF+PGW-C keeps the PDN connection as a PDU session.
    assert!(!oi(crate::s11_build::GtpDeleteAction::InEpsTo5gsHandover));
    assert!(oi(crate::s11_build::GtpDeleteAction::NoAction));
}

#[test]
fn a_delete_bearer_request_names_its_dedicated_ebis_or_its_linked_ebi() {
    use nextgcore_gtp::v2::{Gtp2Header, Gtp2Ie, Gtp2IeType, Gtp2Message};
    let encode = |ies: &[(u8, u8)]| {
        let mut msg = Gtp2Message::new(Gtp2Header::new(99, 1, 7));
        for (instance, ebi) in ies {
            msg.add_ie(Gtp2Ie::new(
                Gtp2IeType::Ebi as u8,
                *instance,
                bytes::Bytes::copy_from_slice(&[*ebi]),
            ));
        }
        msg.encode().to_vec()
    };
    assert_eq!(
        crate::s11_handler::delete_bearer_request_ebis(&encode(&[(1, 6), (1, 7)])),
        vec![6, 7]
    );
    assert_eq!(
        crate::s11_handler::delete_bearer_request_ebis(&encode(&[(0, 5)])),
        vec![5]
    );
}

// ---------------------------------------------------------------------------
// #593: a Location Report reaches the PDN GW that asked (TS 23.401 §5.9.2)
// ---------------------------------------------------------------------------

/// `ue_with_bearers` plus an SGW S11 context and an IMSI, so a Change
/// Notification Request can be built. Returns (mme_ue_id, mme, enb, sess_id).
fn ue_with_sgw(ctx: &MmeContext, enb_id: u64) -> (u64, u32, u32, u64) {
    let (_, mme_ue_id, mme, enb, _) = ue_with_bearers(ctx, enb_id);
    let sgw_ue_id = ctx.sgw_ue_add(1);
    ctx.sgw_ue_pool
        .write()
        .unwrap()
        .get_mut(&sgw_ue_id)
        .unwrap()
        .sgw_s11_teid = 0x5911;
    let sess_id = {
        let mut pool = ctx.mme_ue_pool.write().unwrap();
        let ue = pool.get_mut(&mme_ue_id).unwrap();
        ue.sgw_ue_id = sgw_ue_id;
        ue.imsi[..8].copy_from_slice(&[0x00, 0x01, 0x01, 0x21, 0x43, 0x65, 0x87, 0xF9]);
        ue.imsi_len = 8;
        ue.rat_type = 6;
        ue.sess_list[0]
    };
    (mme_ue_id, mme, enb, sess_id)
}

fn change_notifications_built() -> Vec<nextgcore_gtp::v2::Gtp2Message> {
    crate::gtp_path::CHANGE_NOTIFICATIONS_BUILT
        .lock()
        .unwrap()
        .drain(..)
        .collect()
}

#[test]
fn a_location_report_is_forwarded_to_the_pdn_gw_that_asked() {
    use nextgcore_gtp::v2::Gtp2IeType as T;
    let _guard = crate::gtp_path::lock_s11();
    let (ctx, enb_id) = setup();
    let (mme_ue_id, mme, enb, sess_id) = ue_with_sgw(&ctx, enb_id);
    change_notifications_built();

    // No Change Reporting Action: the report is stored, nothing is sent.
    assert!(handle_s1ap_message(&ctx, enb_id, &location_report(mme, enb)).is_empty());
    assert!(change_notifications_built().is_empty());

    // The PDN GW asks for ECGI reporting (Create Session Response).
    let lrc = crate::s11_handler::apply_change_reporting_action(
        &ctx,
        mme_ue_id,
        &[sess_id],
        Some(crate::s11_handler::change_reporting_action::START_REPORTING_ECGI),
    );
    assert!(lrc.is_some(), "the eNB is asked to report");
    assert_eq!(
        ctx.sess_find_by_id(sess_id)
            .unwrap()
            .change_reporting_action,
        Some(4)
    );

    // Same cell again: no change, nothing sent.
    assert!(handle_s1ap_message(&ctx, enb_id, &location_report(mme, enb)).is_empty());
    assert!(change_notifications_built().is_empty());

    // A new cell: one Change Notification Request for that PDN connection.
    ctx.mme_ue_pool
        .write()
        .unwrap()
        .get_mut(&mme_ue_id)
        .unwrap()
        .e_cgi
        .cell_id = 0x77;
    assert!(handle_s1ap_message(&ctx, enb_id, &location_report(mme, enb)).is_empty());
    let built = change_notifications_built();
    assert_eq!(built.len(), 1);
    let cnr = &built[0];
    assert_eq!(cnr.header.message_type, 38);
    assert_eq!(cnr.header.teid, Some(0x5911));
    assert_eq!(
        cnr.get_ie(T::Imsi as u8, 0).unwrap().value.as_ref(),
        &[0x00, 0x01, 0x01, 0x21, 0x43, 0x65, 0x87, 0xF9]
    );
    assert_eq!(
        cnr.get_ie(T::RatType as u8, 0).unwrap().value.as_ref(),
        &[6]
    );
    let uli = cnr.get_ie(T::Uli as u8, 0).unwrap().value.clone();
    assert_eq!(uli[0], 0x18, "TAI and ECGI present");
    assert_eq!(&uli[4..6], &0x0102u16.to_be_bytes(), "the reported TAC");
    assert_eq!(&uli[9..13], &0xABCDEu32.to_be_bytes(), "the reported cell");
    assert_eq!(
        cnr.get_ie(T::Ebi as u8, 0).unwrap().value.as_ref(),
        &[5],
        "LBI: the default bearer"
    );
    assert_eq!(
        cnr.get_ie(74, 0).unwrap().value.as_ref(),
        &[10, 0, 0, 4],
        "the PGW S5/S8-C address names the PDN connection"
    );
}

#[test]
fn only_the_change_the_pdn_gw_asked_for_is_reported() {
    use crate::s11_handler::{change_reporting_action as a, sessions_to_notify};
    let (ctx, enb_id) = setup();
    let (mme_ue_id, _, _, sess_id) = ue_with_sgw(&ctx, enb_id);
    let set = |action: Option<u8>| {
        ctx.sess_pool
            .write()
            .unwrap()
            .get_mut(&sess_id)
            .unwrap()
            .change_reporting_action = action;
    };
    // (action, tai_changed, ecgi_changed, notified)
    for (action, tai, ecgi, notified) in [
        (None, true, true, false),
        (Some(a::STOP_REPORTING), true, true, false),
        (Some(a::START_REPORTING_ECGI), false, true, true),
        (Some(a::START_REPORTING_ECGI), true, false, false),
        (Some(a::START_REPORTING_TAI), true, false, true),
        (Some(a::START_REPORTING_TAI), false, true, false),
        (Some(a::START_REPORTING_TAI_AND_ECGI), false, true, true),
        (Some(a::START_REPORTING_TAI_AND_ECGI), true, false, true),
        (Some(a::START_REPORTING_TAI_AND_ECGI), false, false, false),
        (Some(1), true, true, false),
    ] {
        set(action);
        assert_eq!(
            !sessions_to_notify(&ctx, mme_ue_id, tai, ecgi).is_empty(),
            notified,
            "action {action:?} tai {tai} ecgi {ecgi}"
        );
    }
}

/// A "stop" from one PDN GW does not stop the eNB reporting another still
/// wants.
#[test]
fn a_stop_from_one_pdn_gw_keeps_reporting_for_another() {
    use crate::s11_handler::{apply_change_reporting_action, change_reporting_action as a};
    let (ctx, enb_id) = setup();
    let (mme_ue_id, _, _, sess_a) = ue_with_sgw(&ctx, enb_id);
    let sess_b = ctx.sess_add(mme_ue_id, 2);
    ctx.mme_ue_pool
        .write()
        .unwrap()
        .get_mut(&mme_ue_id)
        .unwrap()
        .sess_list
        .push(sess_b);
    assert!(apply_change_reporting_action(
        &ctx,
        mme_ue_id,
        &[sess_a, sess_b],
        Some(a::START_REPORTING_ECGI)
    )
    .is_some());
    assert!(
        apply_change_reporting_action(&ctx, mme_ue_id, &[sess_a], Some(a::STOP_REPORTING))
            .is_none(),
        "session B still wants ECGI changes"
    );
    assert!(
        apply_change_reporting_action(&ctx, mme_ue_id, &[sess_b], Some(a::STOP_REPORTING))
            .is_some(),
        "the last stop stops the eNB"
    );
}
