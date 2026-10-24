//! #956: the EPC idle-mode cycle end to end in the MME, against the global
//! context with a real S11 socket (`GtpcServer`) and a stand-in Serving GW
//! socket, and the eNB side read through `s1ap_path`'s tap:
//!
//! 1. S1 release (TS 23.401 §5.3.5): UE CONTEXT RELEASE REQUEST -> Release
//!    Access Bearers Request -> (its response) UE CONTEXT RELEASE COMMAND; the
//!    eNB S1-U endpoints are forgotten.
//! 2. Network triggered service request (§5.3.4.3): Downlink Data Notification
//!    -> Acknowledge to the Serving GW's TEID -> PAGING on the eNB serving the
//!    UE's tracking area; repeated on T3413, and a Failure Indication when the
//!    UE never answers.
//! 3. SERVICE REQUEST (§5.3.4.1): paging stopped -> INITIAL CONTEXT SETUP
//!    REQUEST with every active E-RAB and K_eNB from the request's uplink COUNT
//!    -> (its response) Modify Bearer Request with the eNB S1-U F-TEIDs.

use crate::context::{mme_self, EpsTai, PlmnId};
use crate::gtp_path::{lock_s11, route_s11_for_test, GtpcServer};
use nextgcore_gtp::v2::xact::Gtp2XactConfig;
use nextgcore_gtp::v2::{Gtp2BearerContextIe, Gtp2CauseIe, Gtp2IeType, Gtp2Message};
use nextgcore_s1ap_gen::generated as g;
use std::net::UdpSocket;
use std::time::{Duration, Instant};

const SGW_S11_TEID: u32 = 0x0956_0001;
const SGW_S1U_TEID: u32 = 0x0956_5500;
const KNAS_INT: [u8; 16] = [0x56; 16];

struct Ue {
    mme_ue_id: u64,
    enb_id: u64,
    enb_ue_id: u64,
    local_teid: u32,
    sess_id: u64,
    sgw_ue_id: u64,
    tai: EpsTai,
}

fn enb_addr() -> std::net::SocketAddr {
    UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
}

/// An attached ECM-CONNECTED UE with one PDN connection (EBIs `ebis`), on an
/// eNB that completed S1 Setup advertising the UE's tracking area.
fn seed(tac: u16, ebis: &[u8]) -> Ue {
    let ctx = mme_self();
    let tai = EpsTai {
        plmn_id: PlmnId::new("999", "70"),
        tac,
    };
    let enb_id = ctx.enb_add(enb_addr());
    {
        let mut pool = ctx.enb_pool.write().unwrap();
        let enb = pool.get_mut(&enb_id).unwrap();
        enb.state.s1_setup_success = true;
        enb.supported_ta_list = vec![tai.clone()];
    }
    let enb_ue_id = ctx.enb_ue_add(enb_id, 956);
    let mme_ue_id = ctx.mme_ue_add(enb_ue_id);
    ctx.enb_ue_associate_mme_ue(enb_ue_id, mme_ue_id);
    let sgw_ue_id = ctx.sgw_ue_add(mme_ue_id);
    ctx.sgw_ue_pool
        .write()
        .unwrap()
        .get_mut(&sgw_ue_id)
        .unwrap()
        .sgw_s11_teid = SGW_S11_TEID;
    let sess_id = ctx.sess_add(mme_ue_id, 9);
    let local_teid = {
        let mut pool = ctx.mme_ue_pool.write().unwrap();
        let ue = pool.get_mut(&mme_ue_id).unwrap();
        ue.sgw_ue_id = sgw_ue_id;
        ue.imsi_bcd = format!("99970000956{mme_ue_id:04}");
        ue.sess_list.push(sess_id);
        ue.kasme = [0x11; 32];
        ue.knas_int = KNAS_INT;
        ue.selected_int_algorithm = 2;
        ue.security_context_available = true;
        ue.tai = tai.clone();
        ue.ambr.downlink = 50_000_000;
        ue.ambr.uplink = 20_000_000;
        ue.mme_s11_teid
    };
    for ebi in ebis {
        let bearer_id = ctx.bearer_add(sess_id, mme_ue_id);
        let mut pool = ctx.bearer_pool.write().unwrap();
        let b = pool.get_mut(&bearer_id).unwrap();
        b.ebi = *ebi;
        b.qos.qci = 9;
        b.enb_s1u_teid = 0x1000 + u32::from(*ebi);
        b.enb_s1u_ip.ipv4 = Some([10, 0, 0, 1]);
        b.sgw_s1u_teid = SGW_S1U_TEID + u32::from(*ebi);
        b.sgw_s1u_ip.ipv4 = Some([10, 0, 0, 2]);
        drop(pool);
        ctx.sess_pool
            .write()
            .unwrap()
            .get_mut(&sess_id)
            .unwrap()
            .bearer_list
            .push(bearer_id);
    }
    Ue {
        mme_ue_id,
        enb_id,
        enb_ue_id,
        local_teid,
        sess_id,
        sgw_ue_id,
        tai,
    }
}

fn release(ue: &Ue) {
    let ctx = mme_self();
    ctx.bearer_pool
        .write()
        .unwrap()
        .retain(|_, b| b.mme_ue_id != ue.mme_ue_id);
    ctx.sess_remove(ue.sess_id);
    ctx.mme_ue_remove(ue.mme_ue_id);
    ctx.sgw_ue_pool.write().unwrap().remove(&ue.sgw_ue_id);
}

fn sgw(config: Gtp2XactConfig) -> (UdpSocket, crate::gtp_path::S11TestRoute) {
    let sgw = UdpSocket::bind("127.0.0.1:0").unwrap();
    sgw.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    let server = GtpcServer::open("127.0.0.1:0", config, 7).unwrap();
    let route = route_s11_for_test(server, sgw.local_addr().unwrap());
    (sgw, route)
}

fn recv(sgw: &UdpSocket, msg_type: u8) -> (Gtp2Message, std::net::SocketAddr) {
    let mut buf = [0u8; 4096];
    loop {
        let (len, from) = sgw
            .recv_from(&mut buf)
            .unwrap_or_else(|e| panic!("the SGW must receive message type {msg_type}: {e}"));
        let msg = Gtp2Message::decode(&mut bytes::Bytes::copy_from_slice(&buf[..len])).unwrap();
        if msg.header.message_type == msg_type {
            return (msg, from);
        }
    }
}

fn wait_pdu<T>(enb_id: u64, mut pick: impl FnMut(&g::S1AP_PDU) -> Option<T>) -> T {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        for pdu in crate::s1ap_path::take_tapped_for_test(enb_id) {
            if let Ok(decoded) = nextgcore_s1ap_gen::decode(&pdu) {
                if let Some(t) = pick(&decoded) {
                    return t;
                }
            }
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("no matching S1AP PDU reached eNB {enb_id}");
}

fn is_release_command(pdu: &g::S1AP_PDU) -> Option<()> {
    matches!(
        pdu,
        g::S1AP_PDU::InitiatingMessage(g::InitiatingMessage {
            value: g::InitiatingMessageValue::Id_UEContextRelease(_),
            ..
        })
    )
    .then_some(())
}

fn is_paging(pdu: &g::S1AP_PDU) -> Option<()> {
    matches!(
        pdu,
        g::S1AP_PDU::InitiatingMessage(g::InitiatingMessage {
            value: g::InitiatingMessageValue::Id_Paging(_),
            ..
        })
    )
    .then_some(())
}

/// (E-RAB IDs, Security Key) of an INITIAL CONTEXT SETUP REQUEST.
fn ics(pdu: &g::S1AP_PDU) -> Option<(Vec<u8>, Vec<u8>, bool)> {
    let g::S1AP_PDU::InitiatingMessage(g::InitiatingMessage {
        value: g::InitiatingMessageValue::Id_InitialContextSetup(req),
        ..
    }) = pdu
    else {
        return None;
    };
    use g::InitialContextSetupRequestProtocolIEs_EntryValue as V;
    let (mut erabs, mut key, mut nas) = (Vec::new(), Vec::new(), false);
    for ie in &req.protocol_i_es.0 {
        match &ie.value {
            V::Id_E_RABToBeSetupListCtxtSUReq(l) => {
                for e in &l.0 {
                    let g::E_RABToBeSetupListCtxtSUReq_EntryValue::Id_E_RABToBeSetupItemCtxtSUReq(
                        i,
                    ) = &e.value;
                    erabs.push(i.e_rab_id.0);
                    nas |= i.nas_pdu.is_some();
                }
            }
            V::Id_SecurityKey(k) => key = k.0.clone().into_vec(),
            _ => {}
        }
    }
    Some((erabs, key, nas))
}

/// The NAS-PDU of the first E-RAB of an INITIAL CONTEXT SETUP REQUEST.
fn ics_nas_pdu(pdu: &g::S1AP_PDU) -> Option<Vec<u8>> {
    let g::S1AP_PDU::InitiatingMessage(g::InitiatingMessage {
        value: g::InitiatingMessageValue::Id_InitialContextSetup(req),
        ..
    }) = pdu
    else {
        return None;
    };
    use g::InitialContextSetupRequestProtocolIEs_EntryValue as V;
    req.protocol_i_es.0.iter().find_map(|ie| match &ie.value {
        V::Id_E_RABToBeSetupListCtxtSUReq(l) => l.0.iter().find_map(|e| {
            let g::E_RABToBeSetupListCtxtSUReq_EntryValue::Id_E_RABToBeSetupItemCtxtSUReq(i) =
                &e.value;
            i.nas_pdu.as_ref().map(|n| n.0.clone())
        }),
        _ => None,
    })
}

/// A SERVICE REQUEST (TS 24.301 §8.2.25) with `seq` and a valid short MAC under
/// EIA2, for a UE whose uplink COUNT is `count` once `seq` is applied.
fn service_request(seq: u8, count: u32) -> Vec<u8> {
    let head = [0xc7, seq & 0x1f];
    let mac = crate::nas_security::nas_mac_calculate(2, &KNAS_INT, count, 0, 0, &head);
    vec![head[0], head[1], mac[2], mac[3]]
}

/// S1 release -> ECM-IDLE -> Downlink Data Notification -> paging -> SERVICE
/// REQUEST -> Initial Context Setup -> Modify Bearer Request.
#[test]
fn the_idle_mode_cycle_releases_pages_and_restores_the_user_plane() {
    let _guard = lock_s11();
    let (sgw, _route) = sgw(Gtp2XactConfig::default());
    let ue = seed(0x0956, &[5, 6]);
    let ctx = mme_self();
    crate::s1ap_path::tap_enb_for_test(ue.enb_id);
    let _ = crate::s1ap_path::take_tapped_for_test(ue.enb_id);
    let enb_ue = ctx.enb_ue_find_by_id(ue.enb_ue_id).unwrap();

    // 1. The eNB asks for the release (user inactivity).
    let out = crate::s1ap_handler::handle_ue_context_release_request(
        ctx,
        ue.enb_id,
        &nextgcore_s1ap::UeContextReleaseRequest {
            mme_ue_s1ap_id: enb_ue.mme_ue_s1ap_id,
            enb_ue_s1ap_id: enb_ue.enb_ue_s1ap_id,
            cause: nextgcore_s1ap::Cause::RadioNetwork(
                nextgcore_s1ap::CauseRadioNetwork::UserInactivity,
            ),
        },
    );
    assert!(out.is_empty(), "the command waits for the Serving GW");
    let (rab, from) = recv(&sgw, 170);
    assert_eq!(rab.header.teid, Some(SGW_S11_TEID));
    assert!(
        crate::gtp_path::bearers_of_ue(ctx, ue.mme_ue_id)
            .iter()
            .all(|b| b.enb_s1u_teid == 0),
        "the eNB endpoints are forgotten"
    );
    let mut rsp = Gtp2Message::new(nextgcore_gtp::v2::Gtp2Header::new(
        171,
        ue.local_teid,
        rab.header.sequence_number,
    ));
    rsp.add_ie(Gtp2CauseIe::new(16).to_ie(0));
    sgw.send_to(&rsp.encode(), from).unwrap();
    wait_pdu(ue.enb_id, is_release_command);
    crate::s1ap_handler::handle_ue_context_release_complete(
        ctx,
        ue.enb_id,
        &nextgcore_s1ap::UeContextReleaseComplete {
            mme_ue_s1ap_id: enb_ue.mme_ue_s1ap_id,
            enb_ue_s1ap_id: enb_ue.enb_ue_s1ap_id,
        },
    );
    assert!(
        ctx.mme_ue_find_by_id(ue.mme_ue_id).is_some(),
        "still registered"
    );

    // 2. Downlink data for the now ECM-IDLE UE.
    let mut ddn = Gtp2Message::new(nextgcore_gtp::v2::Gtp2Header::new(
        176,
        ue.local_teid,
        0x956,
    ));
    ddn.add_ie(nextgcore_gtp::v2::Gtp2EbiIe::new(5).to_ie(0));
    sgw.send_to(&ddn.encode(), from).unwrap();
    let (ack, _) = recv(&sgw, 177);
    assert_eq!(
        ack.header.teid,
        Some(SGW_S11_TEID),
        "to the Serving GW's TEID"
    );
    assert_eq!(ack.header.sequence_number, 0x956);
    assert_eq!(
        Gtp2CauseIe::decode(&ack.get_ie(Gtp2IeType::Cause as u8, 0).unwrap().value)
            .unwrap()
            .cause,
        16
    );
    wait_pdu(ue.enb_id, is_paging);
    assert!(ctx
        .mme_ue_find_by_id(ue.mme_ue_id)
        .unwrap()
        .t3413
        .is_running());

    // 3. The UE answers: a new S1 connection carrying the SERVICE REQUEST.
    let new_enb_ue = ctx.enb_ue_add(ue.enb_id, 957);
    ctx.enb_ue_associate_mme_ue(new_enb_ue, ue.mme_ue_id);
    if let Some(e) = ctx.enb_ue_pool.write().unwrap().get_mut(&new_enb_ue) {
        e.saved.tai = ue.tai.clone();
    }
    let count = 1;
    crate::nas_dispatch::nas_eps_handle_uplink(
        ctx,
        crate::nas_dispatch::UplinkNas {
            enb_ue_id: new_enb_ue,
            nas_pdu: &service_request(1, count),
            s_tmsi: None,
        },
    );
    let (erabs, key, nas) = wait_pdu(ue.enb_id, ics);
    assert_eq!(erabs, vec![5, 6], "every active E-RAB");
    assert!(!nas, "no NAS-PDU: a SERVICE REQUEST has no NAS answer");
    assert_eq!(
        key,
        nextgcore_crypt::kdf::nextgcore_kdf_kenb(&[0x11; 32], count).to_vec(),
        "K_eNB from the SERVICE REQUEST's uplink COUNT (TS 33.401 A.3)"
    );
    let mme_ue = ctx.mme_ue_find_by_id(ue.mme_ue_id).unwrap();
    assert!(!mme_ue.t3413.is_running(), "paging stopped");

    // 4. The eNB sets up both E-RABs: the Serving GW is told their endpoints.
    let new = ctx.enb_ue_find_by_id(new_enb_ue).unwrap();
    crate::s1ap_handler::handle_initial_context_setup_response(
        ctx,
        ue.enb_id,
        &nextgcore_s1ap::InitialContextSetupResponse {
            mme_ue_s1ap_id: new.mme_ue_s1ap_id,
            enb_ue_s1ap_id: new.enb_ue_s1ap_id,
            erab_setup_list: [5u8, 6]
                .iter()
                .map(|e| nextgcore_s1ap::ErabSetupItem {
                    erab_id: *e,
                    transport_layer_address: vec![10, 0, 0, 9],
                    gtp_teid: 0x9900 + u32::from(*e),
                })
                .collect(),
            erab_failed_list: vec![],
        },
    );
    let (mbr, _) = recv(&sgw, 34);
    let mut switched: Vec<(u8, u32)> = mbr
        .get_ies(Gtp2IeType::BearerContext as u8)
        .into_iter()
        .filter_map(|ie| {
            let bc = Gtp2BearerContextIe::decode(&ie.value).ok()?;
            let ft = bc.fteid(0).ok().flatten()?;
            Some((bc.ebi().ok()?, ft.teid))
        })
        .collect();
    switched.sort();
    assert_eq!(switched, vec![(5, 0x9905), (6, 0x9906)]);
    ctx.enb_ue_remove(new_enb_ue);
    release(&ue);
}

/// #956: an idle UE that never answers the paging is paged again on each
/// T3413 expiry, and then the Serving GW gets a Downlink Data Notification
/// Failure Indication, cause UE not responding (TS 29.274 §7.2.11.3).
#[test]
fn an_unanswered_paging_is_repeated_then_reported_to_the_serving_gw() {
    let _guard = lock_s11();
    let (sgw, _route) = sgw(Gtp2XactConfig::default());
    let ue = seed(0x0957, &[5]);
    let ctx = mme_self();
    crate::s1ap_path::tap_enb_for_test(ue.enb_id);
    ctx.enb_ue_deassociate_mme_ue(ue.enb_ue_id, ue.mme_ue_id);
    ctx.enb_ue_remove(ue.enb_ue_id);
    let _ = crate::s1ap_path::take_tapped_for_test(ue.enb_id);

    let (_, cause) = crate::s11_handler::downlink_data_notification(ctx, ue.local_teid);
    assert_eq!(cause, crate::s11_build::GtpCause::RequestAccepted);
    wait_pdu(ue.enb_id, is_paging);
    let (_, again) = crate::s11_handler::downlink_data_notification(ctx, ue.local_teid);
    assert_eq!(again, crate::s11_build::GtpCause::RequestAccepted);
    assert!(
        crate::s1ap_path::take_tapped_for_test(ue.enb_id).is_empty(),
        "not paged twice for two notifications"
    );
    for n in 1..=crate::nas_timer::MAX_RETRANSMISSIONS {
        if let Some(u) = ctx.mme_ue_pool.write().unwrap().get_mut(&ue.mme_ue_id) {
            u.t3413.expires_at = Instant::now().checked_sub(Duration::from_secs(1));
        }
        crate::nas_timer::expire_nas_timers(ctx, Instant::now());
        wait_pdu(ue.enb_id, is_paging);
        assert_eq!(
            ctx.mme_ue_find_by_id(ue.mme_ue_id)
                .unwrap()
                .t3413
                .retry_count,
            n,
            "paged again"
        );
    }
    if let Some(u) = ctx.mme_ue_pool.write().unwrap().get_mut(&ue.mme_ue_id) {
        u.t3413.expires_at = Instant::now().checked_sub(Duration::from_secs(1));
    }
    crate::nas_timer::expire_nas_timers(ctx, Instant::now());
    let (fi, _) = recv(&sgw, 70);
    assert_eq!(fi.header.teid, Some(SGW_S11_TEID));
    assert_eq!(
        Gtp2CauseIe::decode(&fi.get_ie(Gtp2IeType::Cause as u8, 0).unwrap().value)
            .unwrap()
            .cause,
        87,
        "UE not responding"
    );
    let u = ctx.mme_ue_find_by_id(ue.mme_ue_id).unwrap();
    assert!(u.paging.failed && !u.t3413.is_running());
    release(&ue);
}

/// #956: Downlink Data Notification Acknowledge causes for the cases that do
/// not page: an unknown TEID is Context not found with TEID 0 (TS 29.274
/// §5.5.2), and an idle UE no eNB serves is Unable to page UE.
#[test]
fn a_downlink_data_notification_that_cannot_page_says_why() {
    let _guard = lock_s11();
    let ctx = mme_self();
    assert_eq!(
        crate::s11_handler::downlink_data_notification(ctx, 0x0956_dead),
        (0, crate::s11_build::GtpCause::ContextNotFound)
    );
    let ue = seed(0x0958, &[5]);
    ctx.enb_ue_deassociate_mme_ue(ue.enb_ue_id, ue.mme_ue_id);
    ctx.enb_ue_remove(ue.enb_ue_id);
    ctx.enb_pool
        .write()
        .unwrap()
        .get_mut(&ue.enb_id)
        .unwrap()
        .supported_ta_list
        .clear();
    assert_eq!(
        crate::s11_handler::downlink_data_notification(ctx, ue.local_teid),
        (SGW_S11_TEID, crate::s11_build::GtpCause::UnableToPageUe)
    );
    release(&ue);
}

/// #956: an EXTENDED SERVICE REQUEST for "packet services via S1" (service
/// type 8) restores the user plane like a SERVICE REQUEST; the E-RAB the eNB
/// fails to set up is deactivated at the core (Delete Bearer Command) and the
/// Modify Bearer Request carries only the one it set up. A failed Initial
/// Context Setup of a SERVICE REQUEST keeps the UE registered.
#[test]
fn a_packet_services_extended_service_request_restores_what_the_enb_sets_up() {
    let _guard = lock_s11();
    let (sgw, _route) = sgw(Gtp2XactConfig::default());
    let ue = seed(0x0959, &[5, 6]);
    let ctx = mme_self();
    crate::s1ap_path::tap_enb_for_test(ue.enb_id);
    ctx.enb_ue_deassociate_mme_ue(ue.enb_ue_id, ue.mme_ue_id);
    ctx.enb_ue_remove(ue.enb_ue_id);
    crate::gtp_path::clear_enb_endpoints(ctx, ue.mme_ue_id);
    let _ = crate::s1ap_path::take_tapped_for_test(ue.enb_id);

    let new_enb_ue = ctx.enb_ue_add(ue.enb_id, 959);
    ctx.enb_ue_associate_mme_ue(new_enb_ue, ue.mme_ue_id);
    // EXTENDED SERVICE REQUEST, integrity protected (header type 1), SQN 0:
    // NAS key set identifier 0, service type 8, M-TMSI identity.
    let inner = [0x07u8, 0x4c, 0x08, 0x05, 0xf4, 0x00, 0x00, 0x09, 0x59];
    let mut signed = vec![0x00u8];
    signed.extend_from_slice(&inner);
    let mac = crate::nas_security::nas_mac_calculate(2, &KNAS_INT, 0, 0, 0, &signed);
    let mut esr = vec![0x17u8];
    esr.extend_from_slice(&mac);
    esr.extend_from_slice(&signed);
    crate::nas_dispatch::nas_eps_handle_uplink(
        ctx,
        crate::nas_dispatch::UplinkNas {
            enb_ue_id: new_enb_ue,
            nas_pdu: &esr,
            s_tmsi: None,
        },
    );
    let (erabs, _, _) = wait_pdu(ue.enb_id, ics);
    assert_eq!(erabs, vec![5, 6]);

    let new = ctx.enb_ue_find_by_id(new_enb_ue).unwrap();
    crate::s1ap_handler::handle_initial_context_setup_response(
        ctx,
        ue.enb_id,
        &nextgcore_s1ap::InitialContextSetupResponse {
            mme_ue_s1ap_id: new.mme_ue_s1ap_id,
            enb_ue_s1ap_id: new.enb_ue_s1ap_id,
            erab_setup_list: vec![nextgcore_s1ap::ErabSetupItem {
                erab_id: 5,
                transport_layer_address: vec![10, 0, 0, 9],
                gtp_teid: 0x9905,
            }],
            erab_failed_list: vec![nextgcore_s1ap::ErabFailedItem {
                erab_id: 6,
                cause: nextgcore_s1ap::Cause::RadioNetwork(
                    nextgcore_s1ap::CauseRadioNetwork::RadioResourcesNotAvailable,
                ),
            }],
        },
    );
    let mut seen = std::collections::BTreeMap::new();
    for _ in 0..2 {
        let mut buf = [0u8; 4096];
        let (len, _) = sgw.recv_from(&mut buf).expect("a message to the SGW");
        let msg = Gtp2Message::decode(&mut bytes::Bytes::copy_from_slice(&buf[..len])).unwrap();
        seen.insert(msg.header.message_type, msg);
    }
    let dbc = seen
        .get(&66)
        .expect("a Delete Bearer Command for the failed E-RAB");
    let ebis: Vec<u8> = dbc
        .get_ies(Gtp2IeType::BearerContext as u8)
        .into_iter()
        .filter_map(|ie| Gtp2BearerContextIe::decode(&ie.value).ok()?.ebi().ok())
        .collect();
    assert_eq!(ebis, vec![6]);
    let mbr = seen.get(&34).expect("a Modify Bearer Request");
    let switched: Vec<u8> = mbr
        .get_ies(Gtp2IeType::BearerContext as u8)
        .into_iter()
        .filter_map(|ie| Gtp2BearerContextIe::decode(&ie.value).ok()?.ebi().ok())
        .collect();
    assert_eq!(switched, vec![5], "only the E-RAB the eNB set up");

    // A later SERVICE REQUEST whose Initial Context Setup fails: S1 is
    // released, the UE stays registered.
    if let Some(u) = ctx.mme_ue_pool.write().unwrap().get_mut(&ue.mme_ue_id) {
        u.service_request_ics_pending = true;
    }
    let _ = crate::s1ap_handler::handle_initial_context_setup_failure(
        ctx,
        ue.enb_id,
        &nextgcore_s1ap::InitialContextSetupFailure {
            mme_ue_s1ap_id: new.mme_ue_s1ap_id,
            enb_ue_s1ap_id: new.enb_ue_s1ap_id,
            cause: nextgcore_s1ap::Cause::RadioNetwork(
                nextgcore_s1ap::CauseRadioNetwork::Unspecified,
            ),
        },
    );
    assert_eq!(
        ctx.enb_ue_find_by_id(new_enb_ue).unwrap().ue_ctx_rel_action,
        crate::context::UeCtxRelAction::S1ContextRemove,
        "S1 only: the UE stays registered"
    );
    ctx.enb_ue_remove(new_enb_ue);
    release(&ue);
}

/// Take `ue` to ECM-IDLE the way the eNB and the Serving GW do: UE CONTEXT
/// RELEASE REQUEST, Release Access Bearers, its Response and the release
/// command. Returns before the UE CONTEXT RELEASE COMPLETE.
fn release_to_command(ue: &Ue, sgw: &UdpSocket) -> nextgcore_s1ap::UeContextReleaseComplete {
    let ctx = mme_self();
    let enb_ue = ctx.enb_ue_find_by_id(ue.enb_ue_id).unwrap();
    let _ = crate::s1ap_handler::handle_ue_context_release_request(
        ctx,
        ue.enb_id,
        &nextgcore_s1ap::UeContextReleaseRequest {
            mme_ue_s1ap_id: enb_ue.mme_ue_s1ap_id,
            enb_ue_s1ap_id: enb_ue.enb_ue_s1ap_id,
            cause: nextgcore_s1ap::Cause::RadioNetwork(
                nextgcore_s1ap::CauseRadioNetwork::UserInactivity,
            ),
        },
    );
    let (rab, from) = recv(sgw, 170);
    let mut rsp = Gtp2Message::new(nextgcore_gtp::v2::Gtp2Header::new(
        171,
        ue.local_teid,
        rab.header.sequence_number,
    ));
    rsp.add_ie(Gtp2CauseIe::new(16).to_ie(0));
    sgw.send_to(&rsp.encode(), from).unwrap();
    wait_pdu(ue.enb_id, is_release_command);
    nextgcore_s1ap::UeContextReleaseComplete {
        mme_ue_s1ap_id: enb_ue.mme_ue_s1ap_id,
        enb_ue_s1ap_id: enb_ue.enb_ue_s1ap_id,
    }
}

/// #961 review MAJOR 1: a Downlink Data Notification that lands between the
/// Release Access Bearers Response and the UE CONTEXT RELEASE COMPLETE (the
/// Serving GW already buffers, the eNB UE context is not yet gone) pages the UE
/// as soon as the release completes. The SGW sends one DDN for that data.
#[test]
fn a_notification_during_the_s1_release_pages_when_it_completes() {
    let _guard = lock_s11();
    let (sgw, _route) = sgw(Gtp2XactConfig::default());
    let ue = seed(0x0961, &[5]);
    let ctx = mme_self();
    crate::s1ap_path::tap_enb_for_test(ue.enb_id);
    let _ = crate::s1ap_path::take_tapped_for_test(ue.enb_id);
    let complete = release_to_command(&ue, &sgw);

    let (_, cause) = crate::s11_handler::downlink_data_notification(ctx, ue.local_teid);
    assert_eq!(cause, crate::s11_build::GtpCause::RequestAccepted);
    assert!(!ctx
        .mme_ue_find_by_id(ue.mme_ue_id)
        .unwrap()
        .t3413
        .is_running());
    crate::s1ap_handler::handle_ue_context_release_complete(ctx, ue.enb_id, &complete);
    wait_pdu(ue.enb_id, is_paging);
    assert!(
        ctx.mme_ue_find_by_id(ue.mme_ue_id)
            .unwrap()
            .t3413
            .is_running(),
        "paged once the release completed"
    );
    release(&ue);
}

/// A TRACKING AREA UPDATE REQUEST (TA updating, no active flag) with the UE's
/// GUTI, integrity protected under EIA2 at uplink COUNT `count`.
fn tau_request(sqn: u8, count: u32) -> Vec<u8> {
    let plain = [
        0x07u8, 0x48, 0x00, 0x0b, 0xf6, 0x99, 0xf9, 0x07, 0x00, 0x02, 0x01, 0x00, 0x00, 0x09, 0x61,
    ];
    let mut signed = vec![sqn];
    signed.extend_from_slice(&plain);
    let mac = crate::nas_security::nas_mac_calculate(2, &KNAS_INT, count, 0, 0, &signed);
    let mut pdu = vec![0x17u8];
    pdu.extend_from_slice(&mac);
    pdu.extend_from_slice(&signed);
    pdu
}

/// #961 review MAJOR 2, TS 24.301 §5.6.2.2.1: a paged UE that answers with a
/// TAU stops the paging (no DDN Failure Indication follows), and because the
/// paging was for downlink data the TAU ACCEPT goes in an Initial Context Setup
/// whose response sends the Modify Bearer Request.
#[test]
fn a_tau_answering_a_data_paging_stops_it_and_restores_the_user_plane() {
    let _guard = lock_s11();
    let (sgw, _route) = sgw(Gtp2XactConfig::default());
    let ue = seed(0x0962, &[5]);
    let ctx = mme_self();
    // A second PDN connection the MME keeps but that was never connected (no
    // S1-U SGW endpoint): reported in the EPS bearer context status, not set up.
    let sess7 = ctx.sess_add(ue.mme_ue_id, 11);
    let b7 = ctx.bearer_add(sess7, ue.mme_ue_id);
    ctx.bearer_pool.write().unwrap().get_mut(&b7).unwrap().ebi = 7;
    ctx.sess_pool
        .write()
        .unwrap()
        .get_mut(&sess7)
        .unwrap()
        .bearer_list
        .push(b7);
    ctx.mme_ue_pool
        .write()
        .unwrap()
        .get_mut(&ue.mme_ue_id)
        .unwrap()
        .sess_list
        .push(sess7);
    crate::s1ap_path::tap_enb_for_test(ue.enb_id);
    let complete = release_to_command(&ue, &sgw);
    crate::s1ap_handler::handle_ue_context_release_complete(ctx, ue.enb_id, &complete);
    let _ = crate::s1ap_path::take_tapped_for_test(ue.enb_id);
    let (_, cause) = crate::s11_handler::downlink_data_notification(ctx, ue.local_teid);
    assert_eq!(cause, crate::s11_build::GtpCause::RequestAccepted);
    wait_pdu(ue.enb_id, is_paging);

    let new_enb_ue = ctx.enb_ue_add(ue.enb_id, 962);
    ctx.enb_ue_associate_mme_ue(new_enb_ue, ue.mme_ue_id);
    if let Some(e) = ctx.enb_ue_pool.write().unwrap().get_mut(&new_enb_ue) {
        e.saved.tai = ue.tai.clone();
    }
    crate::nas_dispatch::nas_eps_handle_uplink(
        ctx,
        crate::nas_dispatch::UplinkNas {
            enb_ue_id: new_enb_ue,
            nas_pdu: &tau_request(0, 0),
            s_tmsi: None,
        },
    );
    let (erabs, key, nas, nas_pdu) = wait_pdu(ue.enb_id, |p| {
        let (erabs, key, nas) = ics(p)?;
        Some((erabs, key, nas, ics_nas_pdu(p)?))
    });
    assert_eq!(
        erabs,
        vec![5],
        "only the bearer established at the Serving GW"
    );
    assert!(nas, "the TAU ACCEPT rides in the Initial Context Setup");
    // EPS bearer context status (IEI 0x57, TS 24.301 §9.9.2.1): every bearer
    // the MME keeps, 5 and 7, not only the one set up (EEA0, so readable).
    let at = nas_pdu
        .windows(2)
        .position(|w| w == [0x57, 0x02])
        .expect("an EPS bearer context status");
    let status = nas_pdu[at + 2];
    assert_eq!(
        status & (1 << 5 | 1 << 7),
        1 << 5 | 1 << 7,
        "EBIs 5 and 7: {status:#04x}"
    );
    assert_eq!(
        key,
        nextgcore_crypt::kdf::nextgcore_kdf_kenb(&[0x11; 32], 0).to_vec()
    );
    assert!(
        !ctx.mme_ue_find_by_id(ue.mme_ue_id)
            .unwrap()
            .t3413
            .is_running(),
        "paging stopped"
    );
    // No Failure Indication, however long T3413 would have run.
    crate::nas_timer::expire_nas_timers(ctx, Instant::now() + Duration::from_secs(60));
    let new = ctx.enb_ue_find_by_id(new_enb_ue).unwrap();
    crate::s1ap_handler::handle_initial_context_setup_response(
        ctx,
        ue.enb_id,
        &nextgcore_s1ap::InitialContextSetupResponse {
            mme_ue_s1ap_id: new.mme_ue_s1ap_id,
            enb_ue_s1ap_id: new.enb_ue_s1ap_id,
            erab_setup_list: vec![nextgcore_s1ap::ErabSetupItem {
                erab_id: 5,
                transport_layer_address: vec![10, 0, 0, 9],
                gtp_teid: 0x9905,
            }],
            erab_failed_list: vec![],
        },
    );
    let mut seen = Vec::new();
    let mut buf = [0u8; 4096];
    while let Ok((len, _)) = sgw.recv_from(&mut buf) {
        let msg = Gtp2Message::decode(&mut bytes::Bytes::copy_from_slice(&buf[..len])).unwrap();
        seen.push(msg.header.message_type);
        if msg.header.message_type == 34 {
            break;
        }
    }
    assert!(seen.contains(&34), "Modify Bearer Request: {seen:?}");
    assert!(!seen.contains(&70), "no DDN Failure Indication: {seen:?}");
    ctx.enb_ue_remove(new_enb_ue);
    release(&ue);
}

/// #961 review round 3, TS 24.301 §5.6.2.2.1: only an INTEGRITY-PROTECTED,
/// verified response stops the paging. A plain TAU REQUEST (anyone who heard
/// the paged S-TMSI could send one) leaves T3413 running and sets up no user
/// plane on a K_eNB from an unverified COUNT.
#[test]
fn an_unprotected_tau_does_not_answer_paging() {
    let _guard = lock_s11();
    let (sgw, _route) = sgw(Gtp2XactConfig::default());
    let ue = seed(0x0965, &[5]);
    let ctx = mme_self();
    crate::s1ap_path::tap_enb_for_test(ue.enb_id);
    let complete = release_to_command(&ue, &sgw);
    crate::s1ap_handler::handle_ue_context_release_complete(ctx, ue.enb_id, &complete);
    let _ = crate::s11_handler::downlink_data_notification(ctx, ue.local_teid);
    wait_pdu(ue.enb_id, is_paging);
    let new_enb_ue = ctx.enb_ue_add(ue.enb_id, 965);
    ctx.enb_ue_associate_mme_ue(new_enb_ue, ue.mme_ue_id);
    // The TAU REQUEST in clear (no security header), and one "protected" under
    // EIA0, which verifies nothing.
    let plain = &tau_request(0, 0)[6..];
    crate::nas_dispatch::nas_eps_handle_uplink(
        ctx,
        crate::nas_dispatch::UplinkNas {
            enb_ue_id: new_enb_ue,
            nas_pdu: plain,
            s_tmsi: None,
        },
    );
    // EIA0 with EEA2: the message decodes (the ciphering is undone) but its
    // integrity is "verified" by the null algorithm, which proves nothing; the
    // decoder must report it unverified (TS 33.401 §5.1.4.2).
    let knas_enc = [0x65u8; 16];
    {
        let mut pool = ctx.mme_ue_pool.write().unwrap();
        let u = pool.get_mut(&ue.mme_ue_id).unwrap();
        u.selected_int_algorithm = 0;
        u.selected_enc_algorithm = 2;
        u.knas_enc = knas_enc;
        u.ul_count = 0;
    }
    let mut body = plain.to_vec();
    crate::nas_security::nas_encrypt(2, &knas_enc, 1, 0, 0, &mut body);
    let mut eia0 = vec![0x27u8, 0, 0, 0, 0, 1];
    eia0.extend_from_slice(&body);
    crate::nas_dispatch::nas_eps_handle_uplink(
        ctx,
        crate::nas_dispatch::UplinkNas {
            enb_ue_id: new_enb_ue,
            nas_pdu: &eia0,
            s_tmsi: None,
        },
    );
    std::thread::sleep(Duration::from_millis(100));
    assert!(
        crate::s1ap_path::take_tapped_for_test(ue.enb_id)
            .iter()
            .filter_map(|p| nextgcore_s1ap_gen::decode(p).ok())
            .all(|p| ics(&p).is_none()),
        "no Initial Context Setup"
    );
    let u = ctx.mme_ue_find_by_id(ue.mme_ue_id).unwrap();
    assert!(u.t3413.is_running(), "paging continues");
    assert!(!u.service_request_ics_pending);
    ctx.enb_ue_remove(new_enb_ue);
    release(&ue);
}

/// #961 review MINORs: a paged UE whose SERVICE REQUEST is rejected stops being
/// paged and the Serving GW is told, cause Service denied (TS 29.274
/// §7.2.11.3); the S1 release clears an outstanding SERVICE REQUEST's Initial
/// Context Setup; and a failed one sends Release Access Bearers so the Serving
/// GW goes back to idle-mode buffering.
#[test]
fn a_rejected_or_failed_service_request_leaves_the_serving_gw_informed() {
    let _guard = lock_s11();
    let (sgw, _route) = sgw(Gtp2XactConfig::default());
    let ue = seed(0x0963, &[5]);
    let ctx = mme_self();
    crate::s1ap_path::tap_enb_for_test(ue.enb_id);
    let complete = release_to_command(&ue, &sgw);
    crate::s1ap_handler::handle_ue_context_release_complete(ctx, ue.enb_id, &complete);
    let _ = crate::s11_handler::downlink_data_notification(ctx, ue.local_teid);
    wait_pdu(ue.enb_id, is_paging);
    // No active bearer any more: the SERVICE REQUEST is rejected with #40.
    let b5 = ctx.bearer_find_by_ebi(ue.mme_ue_id, 5).unwrap();
    ctx.bearer_pool
        .write()
        .unwrap()
        .get_mut(&b5)
        .unwrap()
        .sgw_s1u_teid = 0;
    let new_enb_ue = ctx.enb_ue_add(ue.enb_id, 963);
    ctx.enb_ue_associate_mme_ue(new_enb_ue, ue.mme_ue_id);
    crate::nas_dispatch::nas_eps_handle_uplink(
        ctx,
        crate::nas_dispatch::UplinkNas {
            enb_ue_id: new_enb_ue,
            nas_pdu: &service_request(1, 1),
            s_tmsi: None,
        },
    );
    let (fi, _) = recv(&sgw, 70);
    assert_eq!(
        Gtp2CauseIe::decode(&fi.get_ie(Gtp2IeType::Cause as u8, 0).unwrap().value)
            .unwrap()
            .cause,
        89,
        "Service denied"
    );
    assert!(!ctx
        .mme_ue_find_by_id(ue.mme_ue_id)
        .unwrap()
        .t3413
        .is_running());

    // An outstanding SERVICE REQUEST Initial Context Setup does not survive an
    // S1 release, and one that fails sends Release Access Bearers.
    let enb_ue_2 = ctx.enb_ue_add(ue.enb_id, 964);
    ctx.enb_ue_associate_mme_ue(enb_ue_2, ue.mme_ue_id);
    if let Some(u) = ctx.mme_ue_pool.write().unwrap().get_mut(&ue.mme_ue_id) {
        u.service_request_ics_pending = true;
    }
    let e2 = ctx.enb_ue_find_by_id(enb_ue_2).unwrap();
    let _ = crate::s1ap_handler::handle_initial_context_setup_failure(
        ctx,
        ue.enb_id,
        &nextgcore_s1ap::InitialContextSetupFailure {
            mme_ue_s1ap_id: e2.mme_ue_s1ap_id,
            enb_ue_s1ap_id: e2.enb_ue_s1ap_id,
            cause: nextgcore_s1ap::Cause::RadioNetwork(
                nextgcore_s1ap::CauseRadioNetwork::Unspecified,
            ),
        },
    );
    let _ = recv(&sgw, 170);
    let enb_ue_3 = ctx.enb_ue_add(ue.enb_id, 965);
    ctx.enb_ue_associate_mme_ue(enb_ue_3, ue.mme_ue_id);
    if let Some(u) = ctx.mme_ue_pool.write().unwrap().get_mut(&ue.mme_ue_id) {
        u.service_request_ics_pending = true;
    }
    let e3 = ctx.enb_ue_find_by_id(enb_ue_3).unwrap();
    crate::s1ap_handler::handle_ue_context_release_complete(
        ctx,
        ue.enb_id,
        &nextgcore_s1ap::UeContextReleaseComplete {
            mme_ue_s1ap_id: e3.mme_ue_s1ap_id,
            enb_ue_s1ap_id: e3.enb_ue_s1ap_id,
        },
    );
    assert!(
        !ctx.mme_ue_find_by_id(ue.mme_ue_id)
            .unwrap()
            .service_request_ics_pending,
        "cleared by the S1 release"
    );
    for id in [new_enb_ue, enb_ue_2] {
        ctx.enb_ue_remove(id);
    }
    release(&ue);
}

/// #961 review round 4 (with #916): the Initial Context Setup of a SERVICE
/// REQUEST holds back a UE-AMBR change like any other (`ics_pending_on`): it
/// carries the value computed before the change, and the change is signalled
/// once its response arrives.
#[test]
fn a_ue_ambr_change_during_a_service_request_setup_is_deferred() {
    let _guard = lock_s11();
    let (sgw, _route) = sgw(Gtp2XactConfig::default());
    let ue = seed(0x0966, &[5]);
    let ctx = mme_self();
    crate::s1ap_path::tap_enb_for_test(ue.enb_id);
    let complete = release_to_command(&ue, &sgw);
    crate::s1ap_handler::handle_ue_context_release_complete(ctx, ue.enb_id, &complete);
    if let Some(b) = ctx
        .bearer_find_by_ebi(ue.mme_ue_id, 5)
        .and_then(|id| ctx.sess_find_by_id(ctx.bearer_find_by_id(id)?.sess_id))
    {
        // One active APN of 40 Mbit/s, so a lower subscription changes the UE-AMBR.
        let mut pool = ctx.sess_pool.write().unwrap();
        let s = pool.get_mut(&b.id).unwrap();
        s.ambr.downlink = 40_000_000;
        s.ambr.uplink = 20_000_000;
    }
    let _ = crate::s1ap_path::take_tapped_for_test(ue.enb_id);
    let new_enb_ue = ctx.enb_ue_add(ue.enb_id, 966);
    ctx.enb_ue_associate_mme_ue(new_enb_ue, ue.mme_ue_id);
    crate::nas_dispatch::nas_eps_handle_uplink(
        ctx,
        crate::nas_dispatch::UplinkNas {
            enb_ue_id: new_enb_ue,
            nas_pdu: &service_request(1, 1),
            s_tmsi: None,
        },
    );
    wait_pdu(ue.enb_id, ics);
    assert_eq!(
        ctx.mme_ue_find_by_id(ue.mme_ue_id).unwrap().ics_pending_on,
        new_enb_ue
    );

    let imsi = ctx.mme_ue_find_by_id(ue.mme_ue_id).unwrap().imsi_bcd;
    ctx.mme_ue_set_imsi(ue.mme_ue_id, &imsi);
    crate::s6a_handler::mme_s6a_process_inbound(&crate::fd_path::InboundS6aRequest {
        imsi_bcd: imsi,
        message: crate::fd_path::S6aMessage::Idr(crate::fd_path::IdrMessage {
            idr_flags: 0,
            subscription_data: crate::fd_path::SubscriptionData {
                ambr_downlink: 10_000_000,
                ambr_uplink: 5_000_000,
                ..Default::default()
            },
        }),
    })
    .unwrap();
    assert!(
        ctx.mme_ue_find_by_id(ue.mme_ue_id)
            .unwrap()
            .ue_ambr_deferred,
        "deferred behind the SERVICE REQUEST's setup"
    );
    let new = ctx.enb_ue_find_by_id(new_enb_ue).unwrap();
    crate::s1ap_handler::handle_initial_context_setup_response(
        ctx,
        ue.enb_id,
        &nextgcore_s1ap::InitialContextSetupResponse {
            mme_ue_s1ap_id: new.mme_ue_s1ap_id,
            enb_ue_s1ap_id: new.enb_ue_s1ap_id,
            erab_setup_list: vec![nextgcore_s1ap::ErabSetupItem {
                erab_id: 5,
                transport_layer_address: vec![10, 0, 0, 9],
                gtp_teid: 0x9905,
            }],
            erab_failed_list: vec![],
        },
    );
    assert_eq!(
        ctx.mme_ue_find_by_id(ue.mme_ue_id).unwrap().ics_pending_on,
        0
    );
    assert_eq!(
        crate::s6a_handler::deferred_ue_ambr_sends(ctx).len(),
        1,
        "signalled once the setup is answered"
    );
    ctx.enb_ue_remove(new_enb_ue);
    release(&ue);
}

/// A second PDN connection for `ue`, its default bearer `ebi` active at the
/// Serving GW and (until an S1 release) at the eNB. Returns the session id.
fn add_pdn(ue: &Ue, ebi: u8) -> u64 {
    let ctx = mme_self();
    let sess_id = ctx.sess_add(ue.mme_ue_id, 10);
    let bearer_id = ctx.bearer_add(sess_id, ue.mme_ue_id);
    {
        let mut pool = ctx.bearer_pool.write().unwrap();
        let b = pool.get_mut(&bearer_id).unwrap();
        b.ebi = ebi;
        b.qos.qci = 9;
        b.sgw_s1u_teid = SGW_S1U_TEID + u32::from(ebi);
        b.sgw_s1u_ip.ipv4 = Some([10, 0, 0, 2]);
    }
    ctx.sess_pool
        .write()
        .unwrap()
        .get_mut(&sess_id)
        .unwrap()
        .bearer_list
        .push(bearer_id);
    ctx.mme_ue_pool
        .write()
        .unwrap()
        .get_mut(&ue.mme_ue_id)
        .unwrap()
        .sess_list
        .push(sess_id);
    sess_id
}

/// A Delete Bearer Request for the PDN connection `lbi`, cause reactivation
/// requested.
fn dbr_reactivation(teid: u32, lbi: u8, seq: u32) -> Vec<u8> {
    let mut m = Gtp2Message::new(nextgcore_gtp::v2::Gtp2Header::new(99, teid, seq));
    m.add_ie(nextgcore_gtp::v2::Gtp2Ie::from_slice(
        Gtp2IeType::Ebi as u8,
        0,
        &[lbi],
    ));
    m.add_ie(nextgcore_gtp::v2::Gtp2Ie::from_slice(
        Gtp2IeType::Cause as u8,
        0,
        &[crate::s11_handler::GTP_CAUSE_REACTIVATION_REQUESTED, 0],
    ));
    m.encode().to_vec()
}

fn is_erab_release_command(pdu: &g::S1AP_PDU) -> Option<()> {
    matches!(
        pdu,
        g::S1AP_PDU::InitiatingMessage(g::InitiatingMessage {
            value: g::InitiatingMessageValue::Id_E_RABRelease(_),
            ..
        })
    )
    .then_some(())
}

/// (cause, EBI of the Linked EBI) of a Delete Bearer Response.
fn delete_bearer_response(sgw: &UdpSocket) -> (u8, u32) {
    let (rsp, _) = recv(sgw, 100);
    let cause = Gtp2CauseIe::decode(&rsp.get_ie(Gtp2IeType::Cause as u8, 0).unwrap().value)
        .unwrap()
        .cause;
    (cause, rsp.header.sequence_number)
}

/// #862, TS 23.401 §5.4.4.1 step 4b: a PDN GW initiated deactivation with cause
/// reactivation requested for an ECM-IDLE UE pages it; once the UE is
/// ECM-CONNECTED (SERVICE REQUEST, Initial Context Setup), steps 4c-8 run: the
/// E-RAB RELEASE COMMAND with the DEACTIVATE EPS BEARER CONTEXT REQUEST, and the
/// Delete Bearer Response only after the UE accepts.
#[test]
fn a_reactivation_deactivation_for_an_idle_ue_pages_then_signals() {
    let _guard = lock_s11();
    crate::bearer_deactivation::clear_for_test();
    let (sgw, _route) = sgw(Gtp2XactConfig::default());
    let ue = seed(0x0862, &[5]);
    let _sess6 = add_pdn(&ue, 6);
    let ctx = mme_self();
    crate::s1ap_path::tap_enb_for_test(ue.enb_id);
    let complete = release_to_command(&ue, &sgw);
    crate::s1ap_handler::handle_ue_context_release_complete(ctx, ue.enb_id, &complete);
    let _ = crate::s1ap_path::take_tapped_for_test(ue.enb_id);

    let peer = sgw.local_addr().unwrap();
    crate::s11_handler::dispatch_initial(
        &dbr_reactivation(ue.local_teid, 6, 0x862),
        99,
        0x862,
        peer,
    );
    wait_pdu(ue.enb_id, is_paging);
    assert_eq!(crate::bearer_deactivation::pending_count(), 1, "parked");
    sgw.set_read_timeout(Some(Duration::from_millis(300)))
        .unwrap();
    let mut buf = [0u8; 4096];
    assert!(
        sgw.recv_from(&mut buf).is_err(),
        "the Delete Bearer Response waits for the UE"
    );
    sgw.set_read_timeout(Some(Duration::from_secs(3))).unwrap();

    // The UE answers the paging.
    let new_enb_ue = ctx.enb_ue_add(ue.enb_id, 8620);
    ctx.enb_ue_associate_mme_ue(new_enb_ue, ue.mme_ue_id);
    crate::nas_dispatch::nas_eps_handle_uplink(
        ctx,
        crate::nas_dispatch::UplinkNas {
            enb_ue_id: new_enb_ue,
            nas_pdu: &service_request(1, 1),
            s_tmsi: None,
        },
    );
    let (erabs, _, _) = wait_pdu(ue.enb_id, ics);
    assert_eq!(erabs, vec![5, 6]);
    let new = ctx.enb_ue_find_by_id(new_enb_ue).unwrap();
    crate::s1ap_handler::handle_initial_context_setup_response(
        ctx,
        ue.enb_id,
        &nextgcore_s1ap::InitialContextSetupResponse {
            mme_ue_s1ap_id: new.mme_ue_s1ap_id,
            enb_ue_s1ap_id: new.enb_ue_s1ap_id,
            erab_setup_list: [5u8, 6]
                .iter()
                .map(|e| nextgcore_s1ap::ErabSetupItem {
                    erab_id: *e,
                    transport_layer_address: vec![10, 0, 0, 9],
                    gtp_teid: 0x9900 + u32::from(*e),
                })
                .collect(),
            erab_failed_list: vec![],
        },
    );
    wait_pdu(ue.enb_id, is_erab_release_command);
    let _ = recv(&sgw, 34);
    assert!(crate::bearer_deactivation::on_accept(ctx, ue.mme_ue_id, 6));
    assert_eq!(delete_bearer_response(&sgw), (16, 0x862));
    assert!(ctx.bearer_find_by_ebi(ue.mme_ue_id, 6).is_none());
    assert!(ctx.bearer_find_by_ebi(ue.mme_ue_id, 5).is_some());
    ctx.enb_ue_remove(new_enb_ue);
    release(&ue);
}

/// #984 review: a UE that answers the DeleteBearer paging with an
/// integrity-protected TAU (TS 24.301 §5.6.2.2.1) gets its user plane with the
/// TAU ACCEPT, and the parked deactivation runs on the ICS response.
#[test]
fn a_tau_answering_a_deactivation_paging_runs_the_deactivation() {
    let _guard = lock_s11();
    crate::bearer_deactivation::clear_for_test();
    let (sgw, _route) = sgw(Gtp2XactConfig::default());
    let ue = seed(0x0984, &[5]);
    let _sess6 = add_pdn(&ue, 6);
    let ctx = mme_self();
    crate::s1ap_path::tap_enb_for_test(ue.enb_id);
    let complete = release_to_command(&ue, &sgw);
    crate::s1ap_handler::handle_ue_context_release_complete(ctx, ue.enb_id, &complete);
    let peer = sgw.local_addr().unwrap();
    crate::s11_handler::dispatch_initial(
        &dbr_reactivation(ue.local_teid, 6, 0x984),
        99,
        0x984,
        peer,
    );
    wait_pdu(ue.enb_id, is_paging);

    let new_enb_ue = ctx.enb_ue_add(ue.enb_id, 9840);
    ctx.enb_ue_associate_mme_ue(new_enb_ue, ue.mme_ue_id);
    if let Some(e) = ctx.enb_ue_pool.write().unwrap().get_mut(&new_enb_ue) {
        e.saved.tai = ue.tai.clone();
    }
    crate::nas_dispatch::nas_eps_handle_uplink(
        ctx,
        crate::nas_dispatch::UplinkNas {
            enb_ue_id: new_enb_ue,
            nas_pdu: &tau_request(0, 0),
            s_tmsi: None,
        },
    );
    let (erabs, _, nas) = wait_pdu(ue.enb_id, ics);
    assert!(nas, "the TAU ACCEPT in an Initial Context Setup");
    assert_eq!(erabs, vec![5, 6]);
    let new = ctx.enb_ue_find_by_id(new_enb_ue).unwrap();
    crate::s1ap_handler::handle_initial_context_setup_response(
        ctx,
        ue.enb_id,
        &nextgcore_s1ap::InitialContextSetupResponse {
            mme_ue_s1ap_id: new.mme_ue_s1ap_id,
            enb_ue_s1ap_id: new.enb_ue_s1ap_id,
            erab_setup_list: [5u8, 6]
                .iter()
                .map(|e| nextgcore_s1ap::ErabSetupItem {
                    erab_id: *e,
                    transport_layer_address: vec![10, 0, 0, 9],
                    gtp_teid: 0x9900 + u32::from(*e),
                })
                .collect(),
            erab_failed_list: vec![],
        },
    );
    wait_pdu(ue.enb_id, is_erab_release_command);
    assert!(crate::bearer_deactivation::on_accept(ctx, ue.mme_ue_id, 6));
    assert_eq!(delete_bearer_response(&sgw), (16, 0x984));
    ctx.enb_ue_remove(new_enb_ue);
    release(&ue);
}

/// #862: when the paging fails, the parked deactivation completes in the MME
/// and the Serving GW is answered (the gateway asked for the deletion).
#[test]
fn a_reactivation_deactivation_whose_paging_fails_completes_locally() {
    let _guard = lock_s11();
    crate::bearer_deactivation::clear_for_test();
    let (sgw, _route) = sgw(Gtp2XactConfig::default());
    let ue = seed(0x0863, &[5]);
    let _sess6 = add_pdn(&ue, 6);
    let ctx = mme_self();
    crate::s1ap_path::tap_enb_for_test(ue.enb_id);
    let complete = release_to_command(&ue, &sgw);
    crate::s1ap_handler::handle_ue_context_release_complete(ctx, ue.enb_id, &complete);
    let peer = sgw.local_addr().unwrap();
    crate::s11_handler::dispatch_initial(
        &dbr_reactivation(ue.local_teid, 6, 0x863),
        99,
        0x863,
        peer,
    );
    wait_pdu(ue.enb_id, is_paging);
    for _ in 0..=crate::nas_timer::MAX_RETRANSMISSIONS {
        if let Some(u) = ctx.mme_ue_pool.write().unwrap().get_mut(&ue.mme_ue_id) {
            u.t3413.expires_at = Instant::now().checked_sub(Duration::from_secs(1));
        }
        crate::nas_timer::expire_nas_timers(ctx, Instant::now());
    }
    assert_eq!(delete_bearer_response(&sgw), (16, 0x863));
    assert!(
        ctx.bearer_find_by_ebi(ue.mme_ue_id, 6).is_none(),
        "deleted locally"
    );
    assert_eq!(crate::bearer_deactivation::pending_count(), 0);
    release(&ue);
}

/// #862 (#863 review MINOR 3): a UE that goes ECM-IDLE before it accepts a
/// reactivation-requested deactivation is paged again for it, not settled
/// locally without being told.
#[test]
fn a_ue_going_idle_during_a_reactivation_deactivation_is_paged_again() {
    let _guard = lock_s11();
    crate::bearer_deactivation::clear_for_test();
    let (sgw, _route) = sgw(Gtp2XactConfig::default());
    let ue = seed(0x0864, &[5]);
    let _sess6 = add_pdn(&ue, 6);
    let ctx = mme_self();
    crate::s1ap_path::tap_enb_for_test(ue.enb_id);
    let b6 = ctx.bearer_find_by_ebi(ue.mme_ue_id, 6).unwrap();
    if let Some(b) = ctx.bearer_pool.write().unwrap().get_mut(&b6) {
        b.enb_s1u_teid = 0x1006;
        b.enb_s1u_ip.ipv4 = Some([10, 0, 0, 1]);
    }
    let peer = sgw.local_addr().unwrap();
    crate::s11_handler::dispatch_initial(
        &dbr_reactivation(ue.local_teid, 6, 0x864),
        99,
        0x864,
        peer,
    );
    wait_pdu(ue.enb_id, is_erab_release_command);
    assert_eq!(crate::bearer_deactivation::pending_count(), 1);
    // The UE goes ECM-IDLE without accepting.
    ctx.enb_ue_deassociate_mme_ue(ue.enb_ue_id, ue.mme_ue_id);
    ctx.enb_ue_remove(ue.enb_ue_id);
    crate::bearer_deactivation::sweep(ctx, Instant::now());
    wait_pdu(ue.enb_id, is_paging);
    assert_eq!(
        crate::bearer_deactivation::pending_count(),
        1,
        "parked, not settled"
    );
    assert!(ctx.bearer_find_by_ebi(ue.mme_ue_id, 6).is_some());
    crate::bearer_deactivation::clear_for_test();
    release(&ue);
}

/// #984 review follow-up: an UNPROTECTED TAU does not answer a DeleteBearer
/// paging either (TS 24.301 §5.6.2.2.1): the paging continues, nothing is set
/// up, and the deactivation stays parked.
#[test]
fn an_unprotected_tau_does_not_answer_a_deactivation_paging() {
    let _guard = lock_s11();
    crate::bearer_deactivation::clear_for_test();
    let (sgw, _route) = sgw(Gtp2XactConfig::default());
    let ue = seed(0x0991, &[5]);
    let _sess6 = add_pdn(&ue, 6);
    let ctx = mme_self();
    crate::s1ap_path::tap_enb_for_test(ue.enb_id);
    let complete = release_to_command(&ue, &sgw);
    crate::s1ap_handler::handle_ue_context_release_complete(ctx, ue.enb_id, &complete);
    let peer = sgw.local_addr().unwrap();
    crate::s11_handler::dispatch_initial(
        &dbr_reactivation(ue.local_teid, 6, 0x991),
        99,
        0x991,
        peer,
    );
    wait_pdu(ue.enb_id, is_paging);
    let new_enb_ue = ctx.enb_ue_add(ue.enb_id, 9910);
    ctx.enb_ue_associate_mme_ue(new_enb_ue, ue.mme_ue_id);
    crate::nas_dispatch::nas_eps_handle_uplink(
        ctx,
        crate::nas_dispatch::UplinkNas {
            enb_ue_id: new_enb_ue,
            nas_pdu: &tau_request(0, 0)[6..],
            s_tmsi: None,
        },
    );
    std::thread::sleep(Duration::from_millis(100));
    assert!(
        crate::s1ap_path::take_tapped_for_test(ue.enb_id)
            .iter()
            .filter_map(|p| nextgcore_s1ap_gen::decode(p).ok())
            .all(|p| ics(&p).is_none()),
        "no Initial Context Setup"
    );
    assert!(ctx
        .mme_ue_find_by_id(ue.mme_ue_id)
        .unwrap()
        .t3413
        .is_running());
    assert_eq!(
        crate::bearer_deactivation::pending_count(),
        1,
        "still parked"
    );
    crate::bearer_deactivation::clear_for_test();
    ctx.enb_ue_remove(new_enb_ue);
    release(&ue);
}
