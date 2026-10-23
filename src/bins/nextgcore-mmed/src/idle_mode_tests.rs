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
