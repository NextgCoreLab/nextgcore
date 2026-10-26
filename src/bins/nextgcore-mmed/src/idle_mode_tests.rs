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

pub(crate) const SGW_S11_TEID: u32 = 0x0956_0001;
const SGW_S1U_TEID: u32 = 0x0956_5500;
pub(crate) const KNAS_INT: [u8; 16] = [0x56; 16];

pub(crate) struct Ue {
    pub(crate) mme_ue_id: u64,
    pub(crate) enb_id: u64,
    pub(crate) enb_ue_id: u64,
    pub(crate) local_teid: u32,
    pub(crate) sess_id: u64,
    pub(crate) sgw_ue_id: u64,
    pub(crate) tai: EpsTai,
}

fn enb_addr() -> std::net::SocketAddr {
    UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
}

/// An attached ECM-CONNECTED UE with one PDN connection (EBIs `ebis`), on an
/// eNB that completed S1 Setup advertising the UE's tracking area.
pub(crate) fn seed(tac: u16, ebis: &[u8]) -> Ue {
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

pub(crate) fn release(ue: &Ue) {
    let ctx = mme_self();
    ctx.bearer_pool
        .write()
        .unwrap()
        .retain(|_, b| b.mme_ue_id != ue.mme_ue_id);
    ctx.sess_remove(ue.sess_id);
    ctx.mme_ue_remove(ue.mme_ue_id);
    ctx.sgw_ue_pool.write().unwrap().remove(&ue.sgw_ue_id);
}

pub(crate) fn sgw(config: Gtp2XactConfig) -> (UdpSocket, crate::gtp_path::S11TestRoute) {
    let sgw = UdpSocket::bind("127.0.0.1:0").unwrap();
    sgw.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    let server = GtpcServer::open("127.0.0.1:0", config, 7).unwrap();
    let route = route_s11_for_test(server, sgw.local_addr().unwrap());
    (sgw, route)
}

pub(crate) fn recv(sgw: &UdpSocket, msg_type: u8) -> (Gtp2Message, std::net::SocketAddr) {
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

pub(crate) fn wait_pdu<T>(enb_id: u64, mut pick: impl FnMut(&g::S1AP_PDU) -> Option<T>) -> T {
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

pub(crate) fn is_release_command(pdu: &g::S1AP_PDU) -> Option<()> {
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

/// A Downlink Data Notification for EBI `ebi` from the Serving GW at `sgw` to
/// the MME at `mme`. Returns the Cause of its Acknowledge, and the requests
/// the MME sent while acting on the notification (they precede the
/// Acknowledge on the wire).
fn notify(
    sgw: &UdpSocket,
    mme: std::net::SocketAddr,
    ue: &Ue,
    ebi: u8,
    seq: u32,
) -> (u8, Vec<Gtp2Message>) {
    let mut ddn = Gtp2Message::new(nextgcore_gtp::v2::Gtp2Header::new(176, ue.local_teid, seq));
    ddn.add_ie(nextgcore_gtp::v2::Gtp2EbiIe::new(ebi).to_ie(0));
    sgw.send_to(&ddn.encode(), mme).unwrap();
    let mut before = Vec::new();
    let mut buf = [0u8; 4096];
    let ack = loop {
        let (len, _) = sgw
            .recv_from(&mut buf)
            .expect("the SGW must receive the Downlink Data Notification Acknowledge");
        let msg = Gtp2Message::decode(&mut bytes::Bytes::copy_from_slice(&buf[..len])).unwrap();
        if msg.header.message_type == 177 {
            break msg;
        }
        before.push(msg);
    };
    assert_eq!(ack.header.sequence_number, seq);
    assert_eq!(ack.header.teid, Some(SGW_S11_TEID));
    let cause = Gtp2CauseIe::decode(&ack.get_ie(Gtp2IeType::Cause as u8, 0).unwrap().value)
        .unwrap()
        .cause;
    (cause, before)
}

/// The Release Access Bearers Request among `sent`, else the next one.
fn release_access_bearers(sgw: &UdpSocket, sent: Vec<Gtp2Message>) -> Gtp2Message {
    sent.into_iter()
        .find(|m| m.header.message_type == 170)
        .unwrap_or_else(|| recv(sgw, 170).0)
}

/// Answer the Modify Bearer Request `mbr` with message `cause` and, per
/// bearer, its own cause, and wait until the MME has taken the response.
fn answer_modify_bearer(
    sgw: &UdpSocket,
    mme: std::net::SocketAddr,
    ue: &Ue,
    mbr: &Gtp2Message,
    cause: u8,
    bearers: &[(u8, u8)],
) {
    let mut rsp = Gtp2Message::new(nextgcore_gtp::v2::Gtp2Header::new(
        35,
        ue.local_teid,
        mbr.header.sequence_number,
    ));
    rsp.add_ie(Gtp2CauseIe::new(cause).to_ie(0));
    for (ebi, c) in bearers {
        let mut bc = Gtp2BearerContextIe::new();
        bc.set_ebi(*ebi);
        bc.set_cause(&Gtp2CauseIe::new(*c));
        rsp.add_bearer_context(0, &bc);
    }
    sgw.send_to(&rsp.encode(), mme).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while crate::gtp_path::modify_bearer_in_flight(ue.mme_ue_id) {
        assert!(
            Instant::now() < deadline,
            "the MME must take the Modify Bearer Response"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// The Cause of a UE CONTEXT RELEASE COMMAND.
fn release_command_cause(pdu: &g::S1AP_PDU) -> Option<g::Cause> {
    let g::S1AP_PDU::InitiatingMessage(g::InitiatingMessage {
        value: g::InitiatingMessageValue::Id_UEContextRelease(cmd),
        ..
    }) = pdu
    else {
        return None;
    };
    cmd.protocol_i_es.0.iter().find_map(|ie| match &ie.value {
        g::UEContextReleaseCommandProtocolIEs_EntryValue::Id_Cause(c) => Some(c.clone()),
        _ => None,
    })
}

/// Whether `ue` is still ECM-CONNECTED with nothing released: no UE context
/// release recorded, no paging owed, and its eNB S1-U endpoints kept.
fn untouched(ue: &Ue) -> bool {
    let ctx = mme_self();
    ctx.enb_ue_find_by_id(ue.enb_ue_id)
        .is_some_and(|e| e.ue_ctx_rel_action == crate::context::UeCtxRelAction::Invalid)
        && !ctx
            .mme_ue_find_by_id(ue.mme_ue_id)
            .unwrap()
            .ddn_pending_after_release
        && crate::gtp_path::bearers_of_ue(ctx, ue.mme_ue_id)
            .iter()
            .all(|b| b.enb_s1u_teid != 0)
}

/// #1015, TS 23.401 §5.3.5 / §5.3.4.3: once the Serving GW has accepted the
/// eNB's S1-U F-TEIDs, a Downlink Data Notification for the ECM-CONNECTED UE
/// means the Serving GW released its S1-U (an S1-U path failure with S1-MME
/// up). The MME releases the S1 connection, Transport cause
/// transport-resource-unavailable, the UE goes ECM-IDLE and is paged. Before
/// the Serving GW held the F-TEIDs the same notification changes nothing.
#[test]
fn a_notification_for_a_connected_ue_whose_s1u_was_released_releases_and_pages() {
    let _guard = lock_s11();
    let (sgw, _route) = sgw(Gtp2XactConfig::default());
    let ue = seed(0x1015, &[5, 6]);
    let ctx = mme_self();
    crate::s1ap_path::tap_enb_for_test(ue.enb_id);
    let _ = crate::s1ap_path::take_tapped_for_test(ue.enb_id);

    // The Serving GW never held the eNB's F-TEIDs: S1-U is still being set up.
    let (_, cause) =
        crate::s11_handler::downlink_data_notification_for_bearer(ctx, ue.local_teid, Some(5));
    assert_eq!(cause, crate::s11_build::GtpCause::RequestAccepted);
    assert!(
        untouched(&ue),
        "S1-U not yet at the Serving GW: nothing released"
    );

    // Attach step 23: the Serving GW takes the eNB's F-TEIDs.
    crate::gtp_path::send_modify_bearer_request(
        ctx,
        ue.enb_ue_id,
        ue.mme_ue_id,
        false,
        crate::s11_build::GtpModifyAction::NoAction,
    )
    .unwrap();
    let (mbr, mme) = recv(&sgw, 34);
    answer_modify_bearer(&sgw, mme, &ue, &mbr, 16, &[(5, 16), (6, 16)]);

    // The Serving GW released S1-U (BUFF + NOCP) and notifies downlink.
    let (cause, sent) = notify(&sgw, mme, &ue, 5, 0x1015);
    assert_eq!(cause, 16, "Request accepted");
    let rab = release_access_bearers(&sgw, sent);
    assert_eq!(rab.header.teid, Some(SGW_S11_TEID));
    assert!(
        crate::gtp_path::bearers_of_ue(ctx, ue.mme_ue_id)
            .iter()
            .all(|b| b.enb_s1u_teid == 0 && b.enb_s1u_at_sgw.is_none()),
        "the S1-U bearers are released"
    );
    let mut rsp = Gtp2Message::new(nextgcore_gtp::v2::Gtp2Header::new(
        171,
        ue.local_teid,
        rab.header.sequence_number,
    ));
    rsp.add_ie(Gtp2CauseIe::new(16).to_ie(0));
    sgw.send_to(&rsp.encode(), mme).unwrap();
    assert_eq!(
        wait_pdu(ue.enb_id, release_command_cause),
        g::Cause::Transport(g::CauseTransport(0)),
        "transport-resource-unavailable (TS 36.413 §9.2.1.3)"
    );
    assert!(!ctx
        .mme_ue_find_by_id(ue.mme_ue_id)
        .unwrap()
        .t3413
        .is_running());

    let enb_ue = ctx.enb_ue_find_by_id(ue.enb_ue_id).unwrap();
    crate::s1ap_handler::handle_ue_context_release_complete(
        ctx,
        ue.enb_id,
        &nextgcore_s1ap::UeContextReleaseComplete {
            mme_ue_s1ap_id: enb_ue.mme_ue_s1ap_id,
            enb_ue_s1ap_id: enb_ue.enb_ue_s1ap_id,
        },
    );
    wait_pdu(ue.enb_id, is_paging);
    let mme_ue = ctx.mme_ue_find_by_id(ue.mme_ue_id).unwrap();
    assert!(mme_ue.t3413.is_running(), "paged once ECM-IDLE");
    assert!(ctx.enb_ue_find_by_id(ue.enb_ue_id).is_none(), "ECM-IDLE");
    release(&ue);
}

/// #1015: the notification releases nothing while the Serving GW may lack the
/// eNB's F-TEIDs for a reason that is not a failure: a Modify Bearer Request
/// unanswered, an Initial Context Setup outstanding, or a bearer the Serving GW
/// did not accept (Request accepted partially, TS 29.274 Table 7.2.8-1). A
/// bearer it accepted still counts.
#[test]
fn a_notification_while_s1u_is_being_set_up_releases_nothing() {
    let _guard = lock_s11();
    let (sgw, _route) = sgw(Gtp2XactConfig::default());
    let ue = seed(0x1016, &[5, 6]);
    let ctx = mme_self();
    crate::s1ap_path::tap_enb_for_test(ue.enb_id);
    let _ = crate::s1ap_path::take_tapped_for_test(ue.enb_id);

    crate::gtp_path::send_modify_bearer_request(
        ctx,
        ue.enb_ue_id,
        ue.mme_ue_id,
        false,
        crate::s11_build::GtpModifyAction::NoAction,
    )
    .unwrap();
    let (mbr, mme) = recv(&sgw, 34);
    let (cause, sent) = notify(&sgw, mme, &ue, 5, 0x1016);
    assert_eq!(cause, 16);
    assert!(sent.is_empty(), "nothing sent to the Serving GW");
    assert!(untouched(&ue), "a Modify Bearer Request is in flight");

    // EBI 6 is not accepted.
    answer_modify_bearer(&sgw, mme, &ue, &mbr, 17, &[(5, 16), (6, 73)]);
    let (cause, sent) = notify(&sgw, mme, &ue, 6, 0x1017);
    assert_eq!(cause, 16);
    assert!(sent.is_empty(), "nothing sent to the Serving GW");
    assert!(untouched(&ue), "the Serving GW never held EBI 6's F-TEID");

    // Another Modify Bearer Request (as for a handover) is in flight: the
    // Serving GW may be switching EBI 5's F-TEID.
    crate::gtp_path::send_modify_bearer_request(
        ctx,
        ue.enb_ue_id,
        ue.mme_ue_id,
        false,
        crate::s11_build::GtpModifyAction::NoAction,
    )
    .unwrap();
    let (mbr, _) = recv(&sgw, 34);
    let (cause, sent) = notify(&sgw, mme, &ue, 5, 0x101a);
    assert_eq!(cause, 16);
    assert!(sent.is_empty(), "nothing sent to the Serving GW");
    assert!(untouched(&ue), "a Modify Bearer Request is in flight again");
    answer_modify_bearer(&sgw, mme, &ue, &mbr, 17, &[(5, 16), (6, 73)]);

    ctx.mme_ue_pool
        .write()
        .unwrap()
        .get_mut(&ue.mme_ue_id)
        .unwrap()
        .ics_pending_on = ue.enb_ue_id;
    let (cause, sent) = notify(&sgw, mme, &ue, 5, 0x1018);
    assert_eq!(cause, 16);
    assert!(sent.is_empty(), "nothing sent to the Serving GW");
    assert!(untouched(&ue), "an Initial Context Setup is outstanding");
    ctx.mme_ue_pool
        .write()
        .unwrap()
        .get_mut(&ue.mme_ue_id)
        .unwrap()
        .ics_pending_on = 0;

    // EBI 5 was accepted: its notification is a released S1-U.
    let (cause, sent) = notify(&sgw, mme, &ue, 5, 0x1019);
    assert_eq!(cause, 16);
    let rab = release_access_bearers(&sgw, sent);
    let mut rsp = Gtp2Message::new(nextgcore_gtp::v2::Gtp2Header::new(
        171,
        ue.local_teid,
        rab.header.sequence_number,
    ));
    rsp.add_ie(Gtp2CauseIe::new(16).to_ie(0));
    sgw.send_to(&rsp.encode(), mme).unwrap();
    wait_pdu(ue.enb_id, release_command_cause);
    let enb_ue = ctx.enb_ue_find_by_id(ue.enb_ue_id).unwrap();
    crate::s1ap_handler::handle_ue_context_release_complete(
        ctx,
        ue.enb_id,
        &nextgcore_s1ap::UeContextReleaseComplete {
            mme_ue_s1ap_id: enb_ue.mme_ue_s1ap_id,
            enb_ue_s1ap_id: enb_ue.enb_ue_s1ap_id,
        },
    );
    wait_pdu(ue.enb_id, is_paging);
    release(&ue);
}

/// #1023 review: under a user plane path that stays failed, each S1 release for
/// a released S1-U pages the UE back onto the same dead path. At most two such
/// releases per UE per minute: a third notification in the window releases
/// nothing, and once the window has passed the next one releases again.
#[test]
fn released_s1u_releases_are_bounded_per_window() {
    let _guard = lock_s11();
    let (sgw, _route) = sgw(Gtp2XactConfig::default());
    let ue = seed(0x1023, &[5]);
    let ctx = mme_self();
    crate::s1ap_path::tap_enb_for_test(ue.enb_id);
    let _ = crate::s1ap_path::take_tapped_for_test(ue.enb_id);
    crate::gtp_path::send_modify_bearer_request(
        ctx,
        ue.enb_ue_id,
        ue.mme_ue_id,
        false,
        crate::s11_build::GtpModifyAction::NoAction,
    )
    .unwrap();
    let (mbr, mme) = recv(&sgw, 34);
    answer_modify_bearer(&sgw, mme, &ue, &mbr, 16, &[(5, 16)]);

    // Two releases in the last minute already.
    let now = Instant::now();
    ctx.mme_ue_pool
        .write()
        .unwrap()
        .get_mut(&ue.mme_ue_id)
        .unwrap()
        .stale_s1u_releases = vec![now - Duration::from_secs(20), now - Duration::from_secs(5)];
    let capped0 =
        crate::s11_handler::DDN_RELEASES_CAPPED_TOTAL.load(std::sync::atomic::Ordering::Relaxed);
    let (cause, sent) = notify(&sgw, mme, &ue, 5, 0x1023);
    assert_eq!(cause, 90, "Unable to page UE (TS 29.274 Table 8.4-1)");
    assert!(sent.is_empty(), "no Release Access Bearers");
    assert!(untouched(&ue), "bounded: no third release in the window");
    assert_eq!(
        crate::s11_handler::DDN_RELEASES_CAPPED_TOTAL.load(std::sync::atomic::Ordering::Relaxed),
        capped0 + 1,
        "counted"
    );
    assert!(crate::s11_handler::render_metrics()
        .contains("# TYPE mme_ddn_released_s1u_capped_total counter"));

    // The window has passed: released again.
    ctx.mme_ue_pool
        .write()
        .unwrap()
        .get_mut(&ue.mme_ue_id)
        .unwrap()
        .stale_s1u_releases = vec![now - Duration::from_secs(70), now - Duration::from_secs(61)];
    let (_, sent) = notify(&sgw, mme, &ue, 5, 0x1024);
    let rab = release_access_bearers(&sgw, sent);
    assert_eq!(rab.header.teid, Some(SGW_S11_TEID));
    assert_eq!(
        ctx.mme_ue_find_by_id(ue.mme_ue_id)
            .unwrap()
            .stale_s1u_releases
            .len(),
        1,
        "the old entries pruned, this release recorded"
    );
    let mut rsp = Gtp2Message::new(nextgcore_gtp::v2::Gtp2Header::new(
        171,
        ue.local_teid,
        rab.header.sequence_number,
    ));
    rsp.add_ie(Gtp2CauseIe::new(16).to_ie(0));
    sgw.send_to(&rsp.encode(), mme).unwrap();
    wait_pdu(ue.enb_id, release_command_cause);
    let enb_ue = ctx.enb_ue_find_by_id(ue.enb_ue_id).unwrap();
    crate::s1ap_handler::handle_ue_context_release_complete(
        ctx,
        ue.enb_id,
        &nextgcore_s1ap::UeContextReleaseComplete {
            mme_ue_s1ap_id: enb_ue.mme_ue_s1ap_id,
            enb_ue_s1ap_id: enb_ue.enb_ue_s1ap_id,
        },
    );
    wait_pdu(ue.enb_id, is_paging);
    release(&ue);
}

/// A second PDN connection for `ue`, its default bearer `ebi` active at the
/// Serving GW and (until an S1 release) at the eNB. Returns the session id.
pub(crate) fn add_pdn(ue: &Ue, ebi: u8) -> u64 {
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

/// [`tau_request`] with `extra` optional IEs after the mandatory part.
fn tau_request_with(sqn: u8, count: u32, extra: &[u8]) -> Vec<u8> {
    let mut plain = vec![
        0x07u8, 0x48, 0x00, 0x0b, 0xf6, 0x99, 0xf9, 0x07, 0x00, 0x02, 0x01, 0x00, 0x00, 0x09, 0x61,
    ];
    plain.extend_from_slice(extra);
    let mut signed = vec![sqn];
    signed.extend_from_slice(&plain);
    let mac = crate::nas_security::nas_mac_calculate(2, &KNAS_INT, count, 0, 0, &signed);
    let mut pdu = vec![0x17u8];
    pdu.extend_from_slice(&mac);
    pdu.extend_from_slice(&signed);
    pdu
}

/// The EPS bearer context status bitmap of a TAU ACCEPT in a DOWNLINK NAS
/// TRANSPORT (EEA0, so readable), if it carries one.
fn tau_accept_status(pdu: &g::S1AP_PDU) -> Option<Option<u16>> {
    let g::S1AP_PDU::InitiatingMessage(g::InitiatingMessage {
        value: g::InitiatingMessageValue::Id_downlinkNASTransport(dl),
        ..
    }) = pdu
    else {
        return None;
    };
    dl.protocol_i_es.0.iter().find_map(|ie| match &ie.value {
        g::DownlinkNASTransportProtocolIEs_EntryValue::Id_NAS_PDU(nas) => {
            let nas = &nas.0;
            // 6-octet security header, then 0x07 and the message type.
            if nas.get(7) != Some(&0x49) {
                return None;
            }
            Some(
                nas[8..]
                    .windows(4)
                    .find(|w| w[0] == 0x57 && w[1] == 0x02)
                    .map(|w| u16::from(w[2]) | (u16::from(w[3]) << 8)),
            )
        }
        _ => None,
    })
}

/// #993, TS 24.301 §5.5.3.2.4: a TRACKING AREA UPDATE REQUEST's EPS bearer
/// context status reports dedicated bearer 6 and the default bearer 7 of a
/// second PDN connection inactive. Both are deactivated locally, with no NAS
/// to the UE. The Serving GW gets a Delete Bearer Command for 6 and a Delete
/// Session Request for the second PDN connection, which is removed. The TAU
/// ACCEPT's status lists only EBI 5.
#[test]
fn a_tau_bearer_status_deactivates_what_the_ue_reports_inactive() {
    let _guard = lock_s11();
    let (sgw, _route) = sgw(Gtp2XactConfig::default());
    let ue = seed(0x0993, &[5, 6]);
    let sess7 = add_pdn(&ue, 7);
    let ctx = mme_self();
    crate::s1ap_path::tap_enb_for_test(ue.enb_id);
    let _ = crate::s1ap_path::take_tapped_for_test(ue.enb_id);
    if let Some(e) = ctx.enb_ue_pool.write().unwrap().get_mut(&ue.enb_ue_id) {
        e.saved.tai = ue.tai.clone();
    }
    // Octet 3 = EBI(7)..EBI(0): only EBI 5 active.
    crate::nas_dispatch::nas_eps_handle_uplink(
        ctx,
        crate::nas_dispatch::UplinkNas {
            enb_ue_id: ue.enb_ue_id,
            nas_pdu: &tau_request_with(0, 0, &[0x57, 0x02, 1 << 5, 0x00]),
            s_tmsi: None,
        },
    );
    let status = wait_pdu(ue.enb_id, tau_accept_status);
    assert_eq!(status, Some(1 << 5), "the accept lists only EBI 5");

    let mut types = Vec::new();
    let mut dbc_ebis = Vec::new();
    let mut buf = [0u8; 4096];
    sgw.set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();
    while let Ok((len, _)) = sgw.recv_from(&mut buf) {
        let msg = Gtp2Message::decode(&mut bytes::Bytes::copy_from_slice(&buf[..len])).unwrap();
        if msg.header.message_type == 66 {
            dbc_ebis.extend(
                msg.get_ies(Gtp2IeType::BearerContext as u8)
                    .into_iter()
                    .filter_map(|ie| Gtp2BearerContextIe::decode(&ie.value).ok()?.ebi().ok()),
            );
        }
        types.push(msg.header.message_type);
    }
    assert!(
        types.contains(&36),
        "Delete Session Request for PDN 7: {types:?}"
    );
    assert_eq!(dbc_ebis, vec![6], "Delete Bearer Command for EBI 6");
    assert!(
        ctx.sess_find_by_id(sess7).is_none(),
        "the second PDN connection is removed"
    );
    assert!(!ctx
        .mme_ue_find_by_id(ue.mme_ue_id)
        .unwrap()
        .sess_list
        .contains(&sess7));
    let b6 = ctx
        .bearer_find_by_ebi(ue.mme_ue_id, 6)
        .and_then(|id| ctx.bearer_find_by_id(id))
        .expect("6 waits for the Serving GW's Delete Bearer Request");
    assert!(b6.released_by_enb, "answered then without NAS signalling");
    release(&ue);
}

/// #993: the default bearer of the last remaining PDN connection is kept even
/// when the UE reports it inactive (no EMM-REGISTERED without PDN connection);
/// only the other PDN connection goes.
#[test]
fn a_tau_bearer_status_keeps_the_last_pdn_connection() {
    let _guard = lock_s11();
    let (sgw, _route) = sgw(Gtp2XactConfig::default());
    let ue = seed(0x0994, &[5]);
    let sess7 = add_pdn(&ue, 7);
    let ctx = mme_self();
    crate::s1ap_path::tap_enb_for_test(ue.enb_id);
    let _ = crate::s1ap_path::take_tapped_for_test(ue.enb_id);
    if let Some(e) = ctx.enb_ue_pool.write().unwrap().get_mut(&ue.enb_ue_id) {
        e.saved.tai = ue.tai.clone();
    }
    crate::nas_dispatch::nas_eps_handle_uplink(
        ctx,
        crate::nas_dispatch::UplinkNas {
            enb_ue_id: ue.enb_ue_id,
            nas_pdu: &tau_request_with(0, 0, &[0x57, 0x02, 0x00, 0x00]),
            s_tmsi: None,
        },
    );
    let status = wait_pdu(ue.enb_id, tau_accept_status);
    assert_eq!(status, Some(1 << 5), "the first PDN connection is kept");
    let (_, _) = recv(&sgw, 36);
    assert!(ctx.sess_find_by_id(sess7).is_none());
    assert!(ctx.sess_find_by_id(ue.sess_id).is_some());
    release(&ue);
}

/// The Serving GW's S1-U F-TEID for the dedicated bearer, in [`cbr`].
const DEDICATED_SGW_S1U: u32 = 0x0956_5106;

/// A Create Bearer Request on S11 (TS 29.274 Table 7.2.3-2 at the MME): LBI 5, one
/// Bearer Context with EBI 0, a TFT, the S1-U SGW F-TEID (instance 0), the PGW's
/// S5/S8-U F-TEID (instance 1) and a Bearer QoS of QCI 1, MBR 128 / GBR 64 kbit/s.
fn cbr(teid: u32, seq: u32) -> Vec<u8> {
    use nextgcore_gtp::v2::{Gtp2BearerQosIe, Gtp2EbiIe, Gtp2FTeidIe, Gtp2Ie};
    let mut m = Gtp2Message::new(nextgcore_gtp::v2::Gtp2Header::new(95, teid, seq));
    m.add_ie(Gtp2EbiIe::new(5).to_ie(0));
    let mut bc = Gtp2BearerContextIe::new();
    bc.set_ebi(0);
    bc.add_ie(Gtp2Ie::from_slice(
        Gtp2IeType::BearerTft as u8,
        0,
        &[0x21, 0x31, 0x00, 0x02, 0x30, 0x11],
    ));
    bc.set_fteid(
        0,
        &Gtp2FTeidIe::new_ipv4(1, DEDICATED_SGW_S1U, [10, 0, 0, 2]),
    );
    bc.set_fteid(1, &Gtp2FTeidIe::new_ipv4(5, 0x0bee_f0d1, [10, 0, 0, 3]));
    let mut qos = Gtp2BearerQosIe::new(1, 128, 128, 64, 64);
    qos.pl = 2;
    bc.set_bearer_qos(&qos);
    m.add_bearer_context(0, &bc);
    m.encode().to_vec()
}

/// (E-RAB ID, SGW S1-U TEID, NAS-PDU) of each item of an E-RAB SETUP REQUEST.
fn erab_setup(pdu: &g::S1AP_PDU) -> Option<Vec<(u8, u32, Vec<u8>)>> {
    let g::S1AP_PDU::InitiatingMessage(g::InitiatingMessage {
        value: g::InitiatingMessageValue::Id_E_RABSetup(req),
        ..
    }) = pdu
    else {
        return None;
    };
    use g::E_RABSetupRequestProtocolIEs_EntryValue as V;
    req.protocol_i_es.0.iter().find_map(|ie| match &ie.value {
        V::Id_E_RABToBeSetupListBearerSUReq(l) => Some(
            l.0.iter()
                .map(|e| {
                    let g::E_RABToBeSetupListBearerSUReq_EntryValue::Id_E_RABToBeSetupItemBearerSUReq(
                        item,
                    ) = &e.value;
                    let teid = u32::from_be_bytes(item.gtp_teid.0[..4].try_into().unwrap());
                    (item.e_rab_id.0, teid, item.nas_pdu.0.clone())
                })
                .collect(),
        ),
        _ => None,
    })
}

/// The ECM-CONNECTED, attached UE of a dedicated bearer test.
fn attached(tac: u16) -> Ue {
    let ue = seed(tac, &[5]);
    mme_self()
        .mme_ue_pool
        .write()
        .unwrap()
        .get_mut(&ue.mme_ue_id)
        .unwrap()
        .attach_completed = true;
    ue
}

/// The eNB's E-RAB SETUP RESPONSE for `set_up` (at 10.0.0.9, TEID 0x9900 + E-RAB) and
/// `failed`.
fn erab_setup_response(ue: &Ue, set_up: &[u8], failed: &[u8]) {
    erab_setup_response_at(ue, &[10, 0, 0, 9], set_up, failed);
}

/// The UE's current S1 connection (a paged UE has a new one).
fn current_enb_ue(ue: &Ue) -> crate::context::EnbUe {
    let ctx = mme_self();
    let mme_ue = ctx.mme_ue_find_by_id(ue.mme_ue_id).unwrap();
    ctx.enb_ue_find_by_id(mme_ue.enb_ue_id).unwrap()
}

/// As [`erab_setup_response`], from the eNB transport address `addr`.
fn erab_setup_response_at(ue: &Ue, addr: &[u8], set_up: &[u8], failed: &[u8]) {
    let ctx = mme_self();
    let enb_ue = current_enb_ue(ue);
    crate::s1ap_handler::handle_erab_setup_response(
        ctx,
        enb_ue.enb_id,
        enb_ue.mme_ue_s1ap_id,
        enb_ue.enb_ue_s1ap_id,
        &set_up
            .iter()
            .map(|e| nextgcore_s1ap::ErabSetupItem {
                erab_id: *e,
                transport_layer_address: addr.to_vec(),
                gtp_teid: 0x9900 + u32::from(*e),
            })
            .collect::<Vec<_>>(),
        &failed
            .iter()
            .map(|e| nextgcore_s1ap::ErabFailedItem {
                erab_id: *e,
                cause: nextgcore_s1ap::Cause::RadioNetwork(
                    nextgcore_s1ap::CauseRadioNetwork::Unspecified,
                ),
            })
            .collect::<Vec<_>>(),
    );
}

/// The UE's plain ESM message `esm_type` (0xC6 accept, 0xC7 reject) for EBI `ebi`.
fn ue_esm(ue: &Ue, ebi: u8, esm: &[u8]) {
    let ctx = mme_self();
    let enb_ue = current_enb_ue(ue);
    let mme_ue = ctx.mme_ue_find_by_id(ue.mme_ue_id).unwrap();
    let mut msg = vec![(ebi << 4) | 0x02, 0x00];
    msg.extend_from_slice(esm);
    crate::nas_dispatch::handle_esm_message(ctx, &enb_ue, &mme_ue, &msg);
}

/// (Cause, [(EBI, cause, eNB F-TEID, SGW F-TEID)]) of a Create Bearer Response.
#[allow(clippy::type_complexity)]
fn create_bearer_response(
    sgw: &UdpSocket,
    seq: u32,
) -> (u8, Vec<(u8, u8, Option<(u32, [u8; 4])>, Option<u32>)>) {
    let (rsp, _) = recv(sgw, 96);
    assert_eq!(rsp.header.sequence_number, seq, "the request's number");
    assert_eq!(rsp.header.teid, Some(SGW_S11_TEID), "the Serving GW's TEID");
    let cause = Gtp2CauseIe::decode(&rsp.get_ie(Gtp2IeType::Cause as u8, 0).unwrap().value)
        .unwrap()
        .cause;
    let bcs = rsp
        .get_ies(Gtp2IeType::BearerContext as u8)
        .into_iter()
        .map(|ie| {
            let bc = Gtp2BearerContextIe::decode(&ie.value).unwrap();
            (
                bc.ebi().unwrap(),
                bc.cause().unwrap().unwrap().cause,
                bc.fteid(0)
                    .unwrap()
                    .map(|f| (f.teid, f.ipv4_addr.unwrap_or_default())),
                bc.fteid(1).unwrap().map(|f| f.teid),
            )
        })
        .collect();
    (cause, bcs)
}

fn quiet(sgw: &UdpSocket) -> bool {
    sgw.set_read_timeout(Some(Duration::from_millis(300)))
        .unwrap();
    let mut buf = [0u8; 4096];
    let quiet = sgw.recv_from(&mut buf).is_err();
    sgw.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    quiet
}

/// #641, TS 23.401 §5.4.1 steps 3-8, TS 24.301 §6.4.2: a Create Bearer Request for an
/// ECM-CONNECTED UE gets an EBI (6, the lowest free), an E-RAB SETUP REQUEST to the eNB
/// carrying ACTIVATE DEDICATED EPS BEARER CONTEXT REQUEST, and, only once both the
/// E-RAB SETUP RESPONSE and the UE's ACCEPT have arrived, a Create Bearer Response
/// with the S1-U eNodeB F-TEID (instance 0) and the S1-U SGW F-TEID (instance 1). A
/// retransmitted request is not acted on twice.
#[test]
fn a_create_bearer_request_activates_the_dedicated_bearer() {
    let _guard = lock_s11();
    crate::bearer_activation::clear_for_test();
    let (sgw, route) = sgw(Gtp2XactConfig::default());
    let ue = attached(0x0641);
    let ctx = mme_self();
    let mme = route.server.local_addr();
    crate::s1ap_path::tap_enb_for_test(ue.enb_id);

    sgw.send_to(&cbr(ue.local_teid, 0x0641), mme).unwrap();
    let items = wait_pdu(ue.enb_id, erab_setup);
    assert_eq!(items.len(), 1);
    let (erab, teid, nas) = &items[0];
    assert_eq!(
        (*erab, *teid),
        (6, DEDICATED_SGW_S1U),
        "EBI 6 toward the SGW's S1-U"
    );
    // The protected ESM: 6 octets of security header, then EBI 6 | PD, PTI 0,
    // ACTIVATE DEDICATED EPS BEARER CONTEXT REQUEST, LBI 5, and the EPS QoS (QCI 1, MBR
    // 128 kbit/s = 0x48, GBR 64 kbit/s = 0x40, TS 24.008 Table 10.5.156).
    assert_eq!(&nas[6..10], &[0x62, 0x00, 0xc5, 0x05]);
    assert_eq!(&nas[10..16], &[5, 1, 0x48, 0x48, 0x40, 0x40]);
    assert_eq!(
        &nas[16..],
        &[6, 0x21, 0x31, 0x00, 0x02, 0x30, 0x11],
        "the TFT"
    );
    let bearer = ctx
        .bearer_find_by_ebi(ue.mme_ue_id, 6)
        .and_then(|id| ctx.bearer_find_by_id(id))
        .expect("the bearer is stored with EBI 6");
    assert_eq!(bearer.sess_id, ue.sess_id);
    assert_eq!(bearer.qos.gbr.uplink, 64_000);

    sgw.send_to(&cbr(ue.local_teid, 0x0641), mme).unwrap();
    std::thread::sleep(Duration::from_millis(100));
    assert_eq!(
        crate::bearer_activation::pending_count(),
        1,
        "the retransmission is not a second activation"
    );
    assert!(ctx.bearer_find_by_ebi(ue.mme_ue_id, 7).is_none());
    erab_setup_response(&ue, &[6], &[]);
    assert!(
        quiet(&sgw),
        "no answer before the UE accepts, and none for the retransmission"
    );
    ue_esm(&ue, 6, &[0xc6]);
    let (cause, bcs) = create_bearer_response(&sgw, 0x0641);
    assert_eq!(cause, 16);
    assert_eq!(
        bcs,
        vec![(
            6,
            16,
            Some((0x9906, [10, 0, 0, 9])),
            Some(DEDICATED_SGW_S1U)
        )]
    );
    assert_eq!(crate::bearer_activation::pending_count(), 0);
    assert!(
        ctx.sess_find_by_id(ue.sess_id)
            .unwrap()
            .bearer_list
            .contains(&bearer.id),
        "the bearer stays with its PDN connection"
    );
    release(&ue);
}

/// #641, TS 24.301 §6.4.2.5: the UE rejects the bearer. The Create Bearer Response
/// says "UE refuses" (TS 29.274 §7.2.4), the bearer is removed, and the E-RAB the
/// eNB set up is released again.
#[test]
fn a_dedicated_bearer_the_ue_rejects_is_refused_and_released() {
    let _guard = lock_s11();
    crate::bearer_activation::clear_for_test();
    let (sgw, route) = sgw(Gtp2XactConfig::default());
    let ue = attached(0x0642);
    let ctx = mme_self();
    crate::s1ap_path::tap_enb_for_test(ue.enb_id);
    sgw.send_to(&cbr(ue.local_teid, 0x0642), route.server.local_addr())
        .unwrap();
    let _ = wait_pdu(ue.enb_id, erab_setup);
    erab_setup_response(&ue, &[6], &[]);
    ue_esm(&ue, 6, &[0xc7, 31]);
    let (cause, bcs) = create_bearer_response(&sgw, 0x0642);
    assert_eq!(cause, 88, "UE refuses");
    assert_eq!(bcs, vec![(6, 88, None, None)]);
    assert!(ctx.bearer_find_by_ebi(ue.mme_ue_id, 6).is_none(), "removed");
    wait_pdu(ue.enb_id, is_erab_release_command);
    release(&ue);
}

/// #641: an activation the UE asked for (a Bearer Resource Command's triggered request
/// carries its PTI, TS 29.274 Table 7.2.3-1) sends that PTI in the NAS request (TS
/// 24.301 §6.4.2.2); an E-RAB the eNB fails refuses the bearer without waiting for the UE.
#[test]
fn an_erab_the_enb_fails_refuses_the_bearer_and_the_ues_pti_is_kept() {
    let _guard = lock_s11();
    crate::bearer_activation::clear_for_test();
    let (sgw, route) = sgw(Gtp2XactConfig::default());
    let ue = attached(0x0647);
    let ctx = mme_self();
    crate::s1ap_path::tap_enb_for_test(ue.enb_id);
    let mut req = Gtp2Message::decode(&mut bytes::Bytes::from(cbr(ue.local_teid, 0x0647))).unwrap();
    req.add_ie(nextgcore_gtp::v2::Gtp2Ie::from_slice(
        Gtp2IeType::Pti as u8,
        0,
        &[7],
    ));
    sgw.send_to(&req.encode(), route.server.local_addr())
        .unwrap();
    let items = wait_pdu(ue.enb_id, erab_setup);
    assert_eq!(items[0].2[7], 7, "the UE's PTI");
    erab_setup_response(&ue, &[], &[6]);
    let (cause, bcs) = create_bearer_response(&sgw, 0x0647);
    assert_eq!(cause, 94);
    assert_eq!(bcs, vec![(6, 94, None, None)]);
    assert!(ctx.bearer_find_by_ebi(ue.mme_ue_id, 6).is_none());
    assert_eq!(crate::bearer_activation::pending_count(), 0);
    release(&ue);
}

/// #641, TS 24.301 §6.4.2.6: T3485 retransmits the request four times, and on the
/// fifth expiry the bearer fails "UE not responding".
#[test]
fn a_dedicated_bearer_the_ue_never_answers_fails_after_five_t3485_expiries() {
    let _guard = lock_s11();
    crate::bearer_activation::clear_for_test();
    let (sgw, route) = sgw(Gtp2XactConfig::default());
    let ue = attached(0x0643);
    let ctx = mme_self();
    crate::s1ap_path::tap_enb_for_test(ue.enb_id);
    sgw.send_to(&cbr(ue.local_teid, 0x0643), route.server.local_addr())
        .unwrap();
    let _ = wait_pdu(ue.enb_id, erab_setup);
    erab_setup_response(&ue, &[6], &[]);
    for _ in 0..4 {
        crate::bearer_activation::expire_for_test(ue.mme_ue_id);
        crate::bearer_activation::sweep(ctx, Instant::now());
        assert_eq!(
            crate::bearer_activation::pending_count(),
            1,
            "retransmitted"
        );
    }
    crate::bearer_activation::expire_for_test(ue.mme_ue_id);
    crate::bearer_activation::sweep(ctx, Instant::now());
    let (cause, bcs) = create_bearer_response(&sgw, 0x0643);
    assert_eq!(cause, 87, "UE not responding");
    assert_eq!(bcs, vec![(6, 87, None, None)]);
    assert!(ctx.bearer_find_by_ebi(ue.mme_ue_id, 6).is_none());
    release(&ue);
}

/// Park the Create Bearer Request `seq` behind the paging of `ue`, made ECM-IDLE.
fn paged_cbr(ue: &Ue, seq: u32, sgw: &UdpSocket, mme: std::net::SocketAddr) {
    let ctx = mme_self();
    crate::s1ap_path::tap_enb_for_test(ue.enb_id);
    let complete = release_to_command(ue, sgw);
    crate::s1ap_handler::handle_ue_context_release_complete(ctx, ue.enb_id, &complete);
    let _ = crate::s1ap_path::take_tapped_for_test(ue.enb_id);
    sgw.send_to(&cbr(ue.local_teid, seq), mme).unwrap();
    wait_pdu(ue.enb_id, is_paging);
    assert_eq!(crate::bearer_activation::pending_count(), 1, "parked");
}

/// The EBIs of a GTPv2-C message's Bearer Contexts.
fn bearer_ebis(m: &Gtp2Message) -> Vec<u8> {
    m.get_ies(Gtp2IeType::BearerContext as u8)
        .into_iter()
        .filter_map(|ie| Gtp2BearerContextIe::decode(&ie.value).ok())
        .filter_map(|bc| bc.ebi().ok())
        .collect()
}

/// After the paged UE's Initial Context Setup (`erabs`, which must be only the
/// established bearer 5): its response, the Modify Bearer Request (bearer 5
/// only), then the E-RAB SETUP for 6, the eNB's and the UE's answers, and the
/// Create Bearer Response `seq`.
fn paged_activation_completes(
    ue: &Ue,
    erabs: Vec<u8>,
    sgw: &UdpSocket,
    mme: std::net::SocketAddr,
    seq: u32,
) {
    let ctx = mme_self();
    assert_eq!(
        erabs,
        vec![5],
        "the bearer being activated is not in the ICS"
    );
    let new = current_enb_ue(ue);
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
    let (mbr, _) = recv(sgw, 34);
    assert_eq!(
        bearer_ebis(&mbr),
        vec![5],
        "nor in the Modify Bearer Request"
    );
    answer_modify_bearer(sgw, mme, ue, &mbr, 16, &[(5, 16)]);
    let items = wait_pdu(ue.enb_id, erab_setup);
    assert_eq!(
        items.iter().map(|i| i.0).collect::<Vec<_>>(),
        vec![6],
        "one E-RAB SETUP, for 6"
    );
    erab_setup_response(ue, &[6], &[]);
    ue_esm(ue, 6, &[0xc6]);
    let (cause, bcs) = create_bearer_response(sgw, seq);
    assert_eq!(cause, 16);
    assert_eq!(
        bcs,
        vec![(
            6,
            16,
            Some((0x9906, [10, 0, 0, 9])),
            Some(DEDICATED_SGW_S1U)
        )]
    );
    let b6 = ctx.bearer_find_by_ebi(ue.mme_ue_id, 6).unwrap();
    assert!(
        ctx.sess_find_by_id(ue.sess_id)
            .unwrap()
            .bearer_list
            .contains(&b6),
        "set up: now one of the session's bearers"
    );
    assert_eq!(crate::bearer_activation::pending_count(), 0);
}

/// #1216 review B1, TS 23.401 §5.4.1 step 3: an ECM-IDLE UE paged for a
/// dedicated bearer answers with a SERVICE REQUEST. The Initial Context Setup
/// and the Modify Bearer Request carry only the established bearer, and the new
/// one is set up once, by its own E-RAB SETUP (a second setup of an active E-RAB
/// is "Multiple E-RAB ID instances" at a real eNB, TS 36.413 §8.2.1.4).
#[test]
fn a_paged_activation_sets_the_bearer_up_once_after_the_service_request() {
    let _guard = lock_s11();
    crate::bearer_activation::clear_for_test();
    let (sgw, route) = sgw(Gtp2XactConfig::default());
    let mme = route.server.local_addr();
    let ctx = mme_self();
    let ue = attached(0x1216);
    paged_cbr(&ue, 0x1216, &sgw, mme);

    let new_enb_ue = ctx.enb_ue_add(ue.enb_id, 12160);
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
    paged_activation_completes(&ue, erabs, &sgw, mme, 0x1216);
    ctx.enb_ue_remove(new_enb_ue);
    release(&ue);
}

/// The EPS bearer context status of the TAU ACCEPT in an INITIAL CONTEXT SETUP
/// REQUEST (EEA0, so readable).
fn ics_tau_accept_status(pdu: &g::S1AP_PDU) -> Option<Option<u16>> {
    let nas = ics_nas_pdu(pdu)?;
    (nas.get(7) == Some(&0x49)).then(|| {
        nas[8..]
            .windows(4)
            .find(|w| w[0] == 0x57 && w[1] == 0x02)
            .map(|w| u16::from(w[2]) | (u16::from(w[3]) << 8))
    })
}

/// #1216 review M2 (and B1 on the TAU path): the UE answers the CreateBearer
/// paging with an integrity-protected TAU (TS 24.301 §5.6.2.2.1). Paging stops,
/// the TAU ACCEPT goes in an Initial Context Setup whose EPS bearer context
/// status lists only bearer 5, and the parked activation runs on its response.
#[test]
fn a_tau_answering_an_activation_paging_runs_the_activation() {
    let _guard = lock_s11();
    crate::bearer_activation::clear_for_test();
    let (sgw, route) = sgw(Gtp2XactConfig::default());
    let mme = route.server.local_addr();
    let ctx = mme_self();
    let ue = attached(0x1217);
    paged_cbr(&ue, 0x1217, &sgw, mme);

    let new_enb_ue = ctx.enb_ue_add(ue.enb_id, 12170);
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
    let mut status = None;
    let (erabs, _, nas) = wait_pdu(ue.enb_id, |pdu| {
        status = ics_tau_accept_status(pdu);
        ics(pdu)
    });
    assert!(nas, "the TAU ACCEPT in an Initial Context Setup");
    assert_eq!(
        status,
        Some(Some(1 << 5)),
        "the TAU ACCEPT reports only bearer 5 active"
    );
    assert!(
        !ctx.mme_ue_find_by_id(ue.mme_ue_id)
            .unwrap()
            .t3413
            .is_running(),
        "paging stopped"
    );
    paged_activation_completes(&ue, erabs, &sgw, mme, 0x1217);
    ctx.enb_ue_remove(new_enb_ue);
    release(&ue);
}

/// #1216 review M3 (b): a UE that registered by TAU (or arrived by an N26
/// handover) never had an Attach in this MME; its activation is signalled at
/// once, not held for an ATTACH COMPLETE that will never come.
#[test]
fn an_activation_for_a_ue_registered_by_tau_is_not_held() {
    let _guard = lock_s11();
    crate::bearer_activation::clear_for_test();
    let (sgw, route) = sgw(Gtp2XactConfig::default());
    let ue = seed(0x1218, &[5]);
    let ctx = mme_self();
    ctx.mme_ue_pool
        .write()
        .unwrap()
        .get_mut(&ue.mme_ue_id)
        .unwrap()
        .nas_eps
        .type_ = crate::context::MmeEpsType::TauRequest;
    crate::s1ap_path::tap_enb_for_test(ue.enb_id);
    sgw.send_to(&cbr(ue.local_teid, 0x1218), route.server.local_addr())
        .unwrap();
    let items = wait_pdu(ue.enb_id, erab_setup);
    assert_eq!(items[0].0, 6, "signalled, attach_completed notwithstanding");
    crate::bearer_activation::clear_for_test();
    release(&ue);
}

/// #1216 review M3 (c): the UE context goes (a detach, an implicit detach)
/// while its activation is parked behind paging. The Serving GW is answered
/// "Context not found" and nothing stays pending or stored.
#[test]
fn an_activation_whose_ue_goes_away_is_answered() {
    let _guard = lock_s11();
    crate::bearer_activation::clear_for_test();
    let (sgw, route) = sgw(Gtp2XactConfig::default());
    let mme = route.server.local_addr();
    let ctx = mme_self();
    let ue = attached(0x1219);
    paged_cbr(&ue, 0x1219, &sgw, mme);
    let b6 = ctx
        .bearer_find_by_ebi(ue.mme_ue_id, 6)
        .expect("EBI 6 reserved");
    ctx.mme_ue_remove(ue.mme_ue_id);
    crate::bearer_activation::sweep(ctx, Instant::now());
    let (cause, bcs) = create_bearer_response(&sgw, 0x1219);
    assert_eq!(cause, 64, "Context not found");
    assert_eq!(bcs, vec![(6, 64, None, None)]);
    assert_eq!(crate::bearer_activation::pending_count(), 0);
    assert!(ctx.bearer_find_by_id(b6).is_none(), "the bearer is gone");
    release(&ue);
}

/// #1216 review M5: the MME answers inside the Serving GW's S11 transaction,
/// T3 x (N3 + 1) (TS 29.274 §7.6), whatever T3485 or paging still have to run.
/// A request still held for an Attach that never completes (M3 (a)), and a
/// signalled one the UE has not answered, are refused "UE not responding" at
/// the budget; the E-RAB the eNB set up is released.
#[test]
fn an_activation_is_answered_within_the_serving_gws_transaction() {
    // #1228: sgwcd's S11 window for these Requests.
    let sgw_window = nextgcore_gtp::v2::xact::default_n3_window(
        nextgcore_gtp::v2::xact::SGW_BEARER_PROCEDURE_T3,
    );
    assert!(crate::bearer_activation::answer_budget() < sgw_window);
    assert_eq!(
        crate::bearer_activation::answer_budget(),
        Duration::from_secs(50)
    );
    assert!(
        crate::bearer_activation::T3485_DURATION * 5 < crate::bearer_activation::answer_budget(),
        "T3485 x 5 runs out before the budget"
    );

    let _guard = lock_s11();
    crate::bearer_activation::clear_for_test();
    let (sgw, route) = sgw(Gtp2XactConfig::default());
    let mme = route.server.local_addr();
    let ctx = mme_self();

    // Signalled, the E-RAB up, the UE silent.
    let ue = attached(0x121a);
    crate::s1ap_path::tap_enb_for_test(ue.enb_id);
    sgw.send_to(&cbr(ue.local_teid, 0x121a), mme).unwrap();
    let _ = wait_pdu(ue.enb_id, erab_setup);
    erab_setup_response(&ue, &[6], &[]);
    let just_under = crate::bearer_activation::answer_budget() - Duration::from_millis(500);
    crate::bearer_activation::age_for_test(ue.mme_ue_id, just_under);
    crate::bearer_activation::sweep(ctx, Instant::now());
    assert!(quiet(&sgw), "not before the budget");
    crate::bearer_activation::age_for_test(ue.mme_ue_id, Duration::from_secs(1));
    crate::bearer_activation::sweep(ctx, Instant::now());
    let (cause, bcs) = create_bearer_response(&sgw, 0x121a);
    assert_eq!(cause, 87, "UE not responding");
    assert_eq!(bcs, vec![(6, 87, None, None)]);
    wait_pdu(ue.enb_id, is_erab_release_command);
    release(&ue);

    // Held for an Attach that never completes.
    let ue = seed(0x121b, &[5]);
    ctx.mme_ue_pool
        .write()
        .unwrap()
        .get_mut(&ue.mme_ue_id)
        .unwrap()
        .nas_eps
        .type_ = crate::context::MmeEpsType::AttachRequest;
    sgw.send_to(&cbr(ue.local_teid, 0x121b), mme).unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    while crate::bearer_activation::pending_count() == 0 {
        assert!(Instant::now() < deadline, "the request is held");
        std::thread::sleep(Duration::from_millis(5));
    }
    crate::bearer_activation::age_for_test(ue.mme_ue_id, crate::bearer_activation::answer_budget());
    crate::bearer_activation::sweep(ctx, Instant::now());
    let (cause, _) = create_bearer_response(&sgw, 0x121b);
    assert_eq!(cause, 87);
    assert!(ctx.bearer_find_by_ebi(ue.mme_ue_id, 6).is_none());
    assert_eq!(crate::bearer_activation::pending_count(), 0);
    release(&ue);
}

/// The plain NAS message of a DOWNLINK NAS TRANSPORT (after its 6-octet
/// security header; EEA0, so readable).
fn dl_nas(pdu: &g::S1AP_PDU) -> Option<Vec<u8>> {
    let g::S1AP_PDU::InitiatingMessage(g::InitiatingMessage {
        value: g::InitiatingMessageValue::Id_downlinkNASTransport(dl),
        ..
    }) = pdu
    else {
        return None;
    };
    dl.protocol_i_es.0.iter().find_map(|ie| match &ie.value {
        g::DownlinkNASTransportProtocolIEs_EntryValue::Id_NAS_PDU(nas) => {
            nas.0.get(6..).map(|p| p.to_vec())
        }
        _ => None,
    })
}

/// #641 follow-up, TS 24.301 §7.3.2 g): the UE accepts the dedicated bearer only
/// after the MME refused it to the Serving GW (here the answer budget ran out).
/// The ACCEPT names no bearer: it does not touch the default bearer, and the UE
/// is sent DEACTIVATE EPS BEARER CONTEXT REQUEST for EBI 6, cause #36, once.
#[test]
fn a_late_accept_for_a_refused_bearer_deactivates_it_at_the_ue() {
    let _guard = lock_s11();
    crate::bearer_activation::clear_for_test();
    let (sgw, route) = sgw(Gtp2XactConfig::default());
    let ue = attached(0x1241);
    let ctx = mme_self();
    crate::s1ap_path::tap_enb_for_test(ue.enb_id);
    sgw.send_to(&cbr(ue.local_teid, 0x1241), route.server.local_addr())
        .unwrap();
    let _ = wait_pdu(ue.enb_id, erab_setup);
    erab_setup_response(&ue, &[6], &[]);
    crate::bearer_activation::age_for_test(ue.mme_ue_id, crate::bearer_activation::answer_budget());
    crate::bearer_activation::sweep(ctx, Instant::now());
    let (cause, _) = create_bearer_response(&sgw, 0x1241);
    assert_eq!(cause, 87);
    wait_pdu(ue.enb_id, is_erab_release_command);
    let default_bearer = ctx.bearer_find_by_ebi(ue.mme_ue_id, 5).unwrap();
    let before = ctx.bearer_find_by_id(default_bearer).unwrap();

    ue_esm(&ue, 6, &[0xc6]);
    let nas = wait_pdu(ue.enb_id, |p| dl_nas(p).filter(|n| n.get(2) == Some(&0xcd)));
    assert_eq!(
        nas,
        vec![0x62, 0x00, 0xcd, 36],
        "DEACTIVATE EBI 6, regular deactivation"
    );
    let after = ctx.bearer_find_by_id(default_bearer).unwrap();
    assert_eq!(
        (after.ebi, after.enb_s1u_teid, after.sgw_s1u_teid),
        (before.ebi, before.enb_s1u_teid, before.sgw_s1u_teid),
        "the default bearer is not touched"
    );
    // Once: a second late ACCEPT is ignored (TS 24.301 §7.3.2 g).
    assert!(!crate::bearer_activation::on_unknown_accept(
        ctx,
        ue.mme_ue_id,
        6
    ));
    release(&ue);
}

/// #1245 review: an EBI refused while the UE may still answer for it is not
/// handed to the next activation within the hold: the next bearer gets 7.
#[test]
fn a_refused_ebi_is_not_reused_while_held() {
    let _guard = lock_s11();
    crate::bearer_activation::clear_for_test();
    let (sgw, route) = sgw(Gtp2XactConfig::default());
    let ue = attached(0x1261);
    let ctx = mme_self();
    crate::s1ap_path::tap_enb_for_test(ue.enb_id);
    let mme = route.server.local_addr();
    sgw.send_to(&cbr(ue.local_teid, 0x1261), mme).unwrap();
    let items = wait_pdu(ue.enb_id, erab_setup);
    assert_eq!(items[0].0, 6);
    crate::bearer_activation::age_for_test(ue.mme_ue_id, crate::bearer_activation::answer_budget());
    crate::bearer_activation::sweep(ctx, Instant::now());
    let (cause, _) = create_bearer_response(&sgw, 0x1261);
    assert_eq!(cause, 87, "refused after the UE was signalled");
    sgw.send_to(&cbr(ue.local_teid, 0x1262), mme).unwrap();
    let items = wait_pdu(ue.enb_id, erab_setup);
    assert_eq!(items[0].0, 7, "EBI 6 is held for the UE's late answer");
    crate::bearer_activation::clear_for_test();
    release(&ue);
}

/// Put `ue`'s S1 connection in an S1 handover toward a target context on
/// another eNB; returns the target's id.
fn start_s1_handover(ue: &Ue) -> u64 {
    let ctx = mme_self();
    let target_enb = ctx.enb_add(enb_addr());
    let target = ctx.enb_ue_add(target_enb, 4242);
    ctx.enb_ue_pool
        .write()
        .unwrap()
        .get_mut(&ue.enb_ue_id)
        .unwrap()
        .target_ue_id = target;
    target
}

/// #641 follow-up, TS 23.401 §5.5.1.2.2: a Create Bearer Request during an S1
/// handover pauses its E-RAB SETUP; when the handover is over (here it
/// failed: no target any more) the E-RAB SETUP goes out and the activation
/// completes.
#[test]
fn an_activation_during_an_s1_handover_waits_for_it() {
    let _guard = lock_s11();
    crate::bearer_activation::clear_for_test();
    let (sgw, route) = sgw(Gtp2XactConfig::default());
    let ue = attached(0x1242);
    let ctx = mme_self();
    crate::s1ap_path::tap_enb_for_test(ue.enb_id);
    let target = start_s1_handover(&ue);
    sgw.send_to(&cbr(ue.local_teid, 0x1242), route.server.local_addr())
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    while crate::bearer_activation::pending_count() == 0 {
        assert!(Instant::now() < deadline, "the request is held");
        std::thread::sleep(Duration::from_millis(5));
    }
    crate::bearer_activation::sweep(ctx, Instant::now());
    std::thread::sleep(Duration::from_millis(100));
    assert!(
        crate::s1ap_path::take_tapped_for_test(ue.enb_id)
            .iter()
            .filter_map(|p| nextgcore_s1ap_gen::decode(p).ok())
            .all(|p| erab_setup(&p).is_none()),
        "no E-RAB SETUP while the handover runs"
    );
    // The handover fails: the source keeps the UE.
    ctx.enb_ue_pool
        .write()
        .unwrap()
        .get_mut(&ue.enb_ue_id)
        .unwrap()
        .target_ue_id = crate::context::NEXTGCORE_INVALID_POOL_ID;
    ctx.enb_ue_remove(target);
    crate::bearer_activation::sweep(ctx, Instant::now());
    let items = wait_pdu(ue.enb_id, erab_setup);
    assert_eq!(items[0].0, 6);
    erab_setup_response(&ue, &[6], &[]);
    ue_esm(&ue, 6, &[0xc6]);
    let (cause, _) = create_bearer_response(&sgw, 0x1242);
    assert_eq!(cause, 16);
    release(&ue);
}

/// #641 follow-up, TS 23.401 §5.5.1.1.2: the eNB refuses the E-RAB SETUP as "X2
/// handover triggered" (TS 36.413 §9.2.1.3). That is no failure: the request is
/// re-attempted once the handover is over, toward the UE's new S1 connection
/// after its Path Switch, and completes.
#[test]
fn an_erab_refused_for_a_handover_is_reattempted_after_it() {
    let _guard = lock_s11();
    crate::bearer_activation::clear_for_test();
    let (sgw, route) = sgw(Gtp2XactConfig::default());
    let ue = attached(0x1243);
    let ctx = mme_self();
    crate::s1ap_path::tap_enb_for_test(ue.enb_id);
    sgw.send_to(&cbr(ue.local_teid, 0x1243), route.server.local_addr())
        .unwrap();
    let _ = wait_pdu(ue.enb_id, erab_setup);
    let enb_ue = ctx.enb_ue_find_by_id(ue.enb_ue_id).unwrap();
    crate::s1ap_handler::handle_erab_setup_response(
        ctx,
        ue.enb_id,
        enb_ue.mme_ue_s1ap_id,
        enb_ue.enb_ue_s1ap_id,
        &[],
        &[nextgcore_s1ap::ErabFailedItem {
            erab_id: 6,
            cause: nextgcore_s1ap::Cause::RadioNetwork(
                nextgcore_s1ap::CauseRadioNetwork::X2HandoverTriggered,
            ),
        }],
    );
    assert!(quiet(&sgw), "not refused to the Serving GW");
    assert_eq!(crate::bearer_activation::pending_count(), 1);
    crate::bearer_activation::sweep(ctx, Instant::now());
    std::thread::sleep(Duration::from_millis(100));
    assert!(
        crate::s1ap_path::take_tapped_for_test(ue.enb_id)
            .iter()
            .filter_map(|p| nextgcore_s1ap_gen::decode(p).ok())
            .all(|p| erab_setup(&p).is_none()),
        "not re-sent to the source while the handover runs"
    );
    // The Path Switch moved the UE to a new S1 connection on another eNB.
    let new_enb = ctx.enb_add(enb_addr());
    {
        let mut pool = ctx.enb_pool.write().unwrap();
        pool.get_mut(&new_enb).unwrap().state.s1_setup_success = true;
    }
    let new_enb_ue = ctx.enb_ue_add(new_enb, 12430);
    ctx.enb_ue_associate_mme_ue(new_enb_ue, ue.mme_ue_id);
    crate::s1ap_path::tap_enb_for_test(new_enb);
    crate::bearer_activation::sweep(ctx, Instant::now());
    let items = wait_pdu(new_enb, erab_setup);
    assert_eq!(items[0].0, 6, "re-attempted toward the target");
    erab_setup_response(&ue, &[6], &[]);
    ue_esm(&ue, 6, &[0xc6]);
    let (cause, _) = create_bearer_response(&sgw, 0x1243);
    assert_eq!(cause, 16);
    ctx.enb_ue_remove(new_enb_ue);
    release(&ue);
}

/// #641 follow-up, TS 24.301 §6.4.2.6 b): the PDN connection the dedicated
/// bearer belongs to goes while it is being activated. A PDN GW initiated
/// deactivation of the whole PDN (Delete Bearer Request with its LBI) ends the
/// activation with "Context not found"; a UE's PDN DISCONNECT REQUEST ends it
/// with "UE refuses". Neither leaves a bearer or a pending request.
#[test]
fn an_activation_whose_pdn_goes_ends_locally() {
    let _guard = lock_s11();
    crate::bearer_activation::clear_for_test();
    crate::bearer_deactivation::clear_for_test();
    let (sgw, route) = sgw(Gtp2XactConfig::default());
    let mme = route.server.local_addr();
    let ctx = mme_self();
    let ue = attached(0x1244);
    let _sess6 = add_pdn(&ue, 6);
    crate::s1ap_path::tap_enb_for_test(ue.enb_id);

    // The PGW deletes the PDN of LBI 5 while EBI 7 is being activated on it.
    sgw.send_to(&cbr(ue.local_teid, 0x1244), mme).unwrap();
    let items = wait_pdu(ue.enb_id, erab_setup);
    assert_eq!(items[0].0, 7);
    crate::s11_handler::dispatch_initial(
        &dbr_reactivation(ue.local_teid, 5, 0x1245),
        99,
        0x1245,
        sgw.local_addr().unwrap(),
    );
    let (cause, bcs) = create_bearer_response(&sgw, 0x1244);
    assert_eq!(cause, 64);
    assert_eq!(bcs, vec![(7, 64, None, None)]);
    assert!(ctx.bearer_find_by_ebi(ue.mme_ue_id, 7).is_none());
    assert_eq!(crate::bearer_activation::pending_count(), 0);
    crate::bearer_deactivation::clear_for_test();
    release(&ue);

    // The UE disconnects the PDN.
    let ue = attached(0x1246);
    crate::s1ap_path::tap_enb_for_test(ue.enb_id);
    sgw.send_to(&cbr(ue.local_teid, 0x1246), mme).unwrap();
    let _ = wait_pdu(ue.enb_id, erab_setup);
    let enb_ue = current_enb_ue(&ue);
    let mme_ue = ctx.mme_ue_find_by_id(ue.mme_ue_id).unwrap();
    crate::nas_dispatch::handle_esm_message(ctx, &enb_ue, &mme_ue, &[0x02, 0x01, 0xd2, 0x05]);
    let (cause, _) = create_bearer_response(&sgw, 0x1246);
    assert_eq!(cause, 88, "UE refuses");
    assert!(ctx.bearer_find_by_ebi(ue.mme_ue_id, 6).is_none());
    assert_eq!(crate::bearer_activation::pending_count(), 0);
    release(&ue);
}

/// #1216 review: a Create Bearer Request without its Linked EBI (M, TS 29.274
/// Table 7.2.3-1) is answered 70 Mandatory IE missing naming the EBI as the
/// Offending IE (§8.4); a Bearer QoS too short to parse is 69 Mandatory IE
/// incorrect, not "missing".
#[test]
fn a_create_bearer_request_with_a_bad_ie_names_the_fault() {
    use nextgcore_gtp::v2::{Gtp2FTeidIe, Gtp2Ie};
    let _guard = lock_s11();
    crate::bearer_activation::clear_for_test();
    let (sgw, route) = sgw(Gtp2XactConfig::default());
    let mme = route.server.local_addr();
    let ue = attached(0x121d);

    let mut no_lbi =
        Gtp2Message::decode(&mut bytes::Bytes::from(cbr(ue.local_teid, 0x121d))).unwrap();
    no_lbi.ies.retain(|ie| ie.ie_type != Gtp2IeType::Ebi as u8);
    sgw.send_to(&no_lbi.encode(), mme).unwrap();
    let (rsp, _) = recv(&sgw, 96);
    assert_eq!(
        rsp.get_ie(Gtp2IeType::Cause as u8, 0)
            .unwrap()
            .value
            .to_vec(),
        vec![70, 0, Gtp2IeType::Ebi as u8, 0, 0, 0]
    );

    let mut short = Gtp2Message::new(nextgcore_gtp::v2::Gtp2Header::new(
        95,
        ue.local_teid,
        0x121e,
    ));
    short.add_ie(nextgcore_gtp::v2::Gtp2EbiIe::new(5).to_ie(0));
    let mut bc = Gtp2BearerContextIe::new();
    bc.set_ebi(0);
    bc.add_ie(Gtp2Ie::from_slice(
        Gtp2IeType::BearerTft as u8,
        0,
        &[0x21, 0x31, 0x00, 0x02, 0x30, 0x11],
    ));
    bc.set_fteid(
        0,
        &Gtp2FTeidIe::new_ipv4(1, DEDICATED_SGW_S1U, [10, 0, 0, 2]),
    );
    bc.add_ie(Gtp2Ie::from_slice(
        Gtp2IeType::BearerQos as u8,
        0,
        &[0x08, 1, 0, 0],
    ));
    short.add_bearer_context(0, &bc);
    sgw.send_to(&short.encode(), mme).unwrap();
    let (cause, bcs) = create_bearer_response(&sgw, 0x121e);
    assert_eq!(cause, 69);
    assert_eq!(bcs, vec![(0, 69, None, None)]);
    release(&ue);
}

/// #1216 review M4: an IPv6-only eNB S1-U. The accepted bearer's Create Bearer
/// Response carries the S1-U eNodeB F-TEID with the IPv6 address (TS 29.274
/// Table 7.2.4-2), not cause 16 without it.
#[test]
fn an_ipv6_enb_s1u_is_answered_in_the_create_bearer_response() {
    let _guard = lock_s11();
    crate::bearer_activation::clear_for_test();
    let (sgw, route) = sgw(Gtp2XactConfig::default());
    let ue = attached(0x121c);
    crate::s1ap_path::tap_enb_for_test(ue.enb_id);
    sgw.send_to(&cbr(ue.local_teid, 0x121c), route.server.local_addr())
        .unwrap();
    let _ = wait_pdu(ue.enb_id, erab_setup);
    let v6: [u8; 16] = [
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x09,
    ];
    erab_setup_response_at(&ue, &v6, &[6], &[]);
    ue_esm(&ue, 6, &[0xc6]);
    let (rsp, _) = recv(&sgw, 96);
    let bc = Gtp2BearerContextIe::decode(
        &rsp.get_ie(Gtp2IeType::BearerContext as u8, 0)
            .unwrap()
            .value,
    )
    .unwrap();
    assert_eq!(bc.cause().unwrap().unwrap().cause, 16);
    let enb = bc.fteid(0).unwrap().expect("the S1-U eNodeB F-TEID");
    assert_eq!(
        (enb.teid, enb.ipv6_addr, enb.ipv4_addr),
        (0x9906, Some(v6), None)
    );
    let sgw_f = bc.fteid(1).unwrap().expect("the S1-U SGW F-TEID");
    assert_eq!(sgw_f.ipv4_addr, Some([10, 0, 0, 2]));
    release(&ue);
}

/// An established dedicated bearer `ebi` on `ue`'s PDN connection (QCI 1, MBR
/// 128 kbit/s, GBR 64 kbit/s, a TFT), and that PDN's APN-AMBR at 1 Mbit/s.
fn with_dedicated(ue: &Ue, ebi: u8) -> u64 {
    let ctx = mme_self();
    let id = ctx.bearer_add(ue.sess_id, ue.mme_ue_id);
    if let Some(b) = ctx.bearer_pool.write().unwrap().get_mut(&id) {
        b.ebi = ebi;
        b.qos.qci = 1;
        b.qos.arp.priority_level = 2;
        b.qos.mbr.uplink = 128_000;
        b.qos.mbr.downlink = 128_000;
        b.qos.gbr.uplink = 64_000;
        b.qos.gbr.downlink = 64_000;
        b.tft = vec![0x21, 0x31, 0x00, 0x02, 0x30, 0x11];
        b.sgw_s1u_teid = DEDICATED_SGW_S1U;
        b.sgw_s1u_ip.ipv4 = Some([10, 0, 0, 2]);
        b.enb_s1u_teid = 0x9906;
        b.enb_s1u_ip.ipv4 = Some([10, 0, 0, 9]);
    }
    if let Some(s) = ctx.sess_pool.write().unwrap().get_mut(&ue.sess_id) {
        s.bearer_list.push(id);
        s.ambr.downlink = 1_000_000;
        s.ambr.uplink = 1_000_000;
    }
    id
}

/// An Update Bearer Request (TS 29.274 §7.2.15) to `teid` for EBI `ebi`, with a new
/// Bearer QoS (MBR 256 kbit/s) if `qos`, a new TFT if `tft`, and the APN-AMBR
/// `ambr_kbps` (M).
fn ubr(teid: u32, seq: u32, ebi: u8, qos: bool, tft: bool, ambr_kbps: Option<u32>) -> Vec<u8> {
    use nextgcore_gtp::v2::{Gtp2BearerQosIe, Gtp2EbiIe, Gtp2Ie};
    let mut m = Gtp2Message::new(nextgcore_gtp::v2::Gtp2Header::new(97, teid, seq));
    let mut bc = Gtp2BearerContextIe::new();
    bc.set_ebi(ebi);
    if tft {
        bc.add_ie(Gtp2Ie::from_slice(
            Gtp2IeType::BearerTft as u8,
            0,
            &[0x21, 0x31, 0x00, 0x02, 0x30, 0x22],
        ));
    }
    if qos {
        let mut q = Gtp2BearerQosIe::new(1, 256, 256, 64, 64);
        q.pl = 2;
        bc.set_bearer_qos(&q);
    }
    m.add_bearer_context(0, &bc);
    let _ = Gtp2EbiIe::new(0);
    if let Some(k) = ambr_kbps {
        let mut v = k.to_be_bytes().to_vec();
        v.extend_from_slice(&k.to_be_bytes());
        m.add_ie(Gtp2Ie::from_slice(Gtp2IeType::Ambr as u8, 0, &v));
    }
    m.encode().to_vec()
}

/// (E-RAB IDs and NAS-PDUs, UE-AMBR present) of an E-RAB MODIFY REQUEST.
fn erab_modify(pdu: &g::S1AP_PDU) -> Option<(Vec<(u8, Vec<u8>)>, bool)> {
    let g::S1AP_PDU::InitiatingMessage(g::InitiatingMessage {
        value: g::InitiatingMessageValue::Id_E_RABModify(req),
        ..
    }) = pdu
    else {
        return None;
    };
    use g::E_RABModifyRequestProtocolIEs_EntryValue as V;
    let (mut items, mut ambr) = (Vec::new(), false);
    for ie in &req.protocol_i_es.0 {
        match &ie.value {
            V::Id_E_RABToBeModifiedListBearerModReq(l) => {
                for e in &l.0 {
                    let g::E_RABToBeModifiedListBearerModReq_EntryValue::Id_E_RABToBeModifiedItemBearerModReq(
                        i,
                    ) = &e.value;
                    items.push((i.e_rab_id.0, i.nas_pdu.0.clone()));
                }
            }
            V::Id_uEaggregateMaximumBitrate(_) => ambr = true,
            _ => {}
        }
    }
    Some((items, ambr))
}

/// (Cause, [(EBI, cause)]) of an Update Bearer Response.
fn update_bearer_response(sgw: &UdpSocket, seq: u32) -> (u8, Vec<(u8, u8)>) {
    let (rsp, _) = recv(sgw, 98);
    assert_eq!(rsp.header.sequence_number, seq, "the request's number");
    let cause = rsp.get_ie(Gtp2IeType::Cause as u8, 0).unwrap().value[0];
    let bcs = rsp
        .get_ies(Gtp2IeType::BearerContext as u8)
        .into_iter()
        .map(|ie| {
            let bc = Gtp2BearerContextIe::decode(&ie.value).unwrap();
            (bc.ebi().unwrap(), bc.cause().unwrap().unwrap().cause)
        })
        .collect();
    (cause, bcs)
}

fn erab_modify_response(ue: &Ue, modified: &[u8]) {
    let enb_ue = current_enb_ue(ue);
    crate::s1ap_handler::handle_erab_modify_response(
        mme_self(),
        enb_ue.enb_id,
        enb_ue.mme_ue_s1ap_id,
        enb_ue.enb_ue_s1ap_id,
        modified,
        &[],
    );
}

/// #641 Update half, TS 23.401 §5.4.2.1, TS 24.301 §6.4.3: an Update Bearer
/// Request changing a dedicated bearer's QoS. The eNB gets an E-RAB MODIFY
/// REQUEST carrying MODIFY EPS BEARER CONTEXT REQUEST with the New EPS QoS; the
/// Update Bearer Response (cause 16) waits for both the E-RAB MODIFY RESPONSE and
/// the UE's ACCEPT, and the bearer has its new QoS.
#[test]
fn an_update_bearer_request_modifies_the_bearer_qos() {
    let _guard = lock_s11();
    crate::bearer_activation::clear_for_test();
    let (sgw, route) = sgw(Gtp2XactConfig::default());
    let ue = attached(0x1271);
    let b6 = with_dedicated(&ue, 6);
    let ctx = mme_self();
    crate::s1ap_path::tap_enb_for_test(ue.enb_id);
    sgw.send_to(
        &ubr(ue.local_teid, 0x1271, 6, true, false, Some(1000)),
        route.server.local_addr(),
    )
    .unwrap();
    let (items, ambr) = wait_pdu(ue.enb_id, erab_modify);
    assert_eq!(items.len(), 1);
    assert!(!ambr, "the APN-AMBR did not change");
    let (erab, nas) = &items[0];
    assert_eq!(*erab, 6);
    // Security header, then EBI 6 | PD, PTI 0, MODIFY EPS BEARER CONTEXT REQUEST,
    // New EPS QoS (0x5B, QCI 1, MBR 256 kbit/s = 0x58, GBR 64 = 0x40), no TFT.
    assert_eq!(&nas[6..9], &[0x62, 0x00, 0xc9]);
    assert_eq!(&nas[9..11], &[0x5b, 5]);
    assert_eq!(&nas[11..16], &[1, 0x58, 0x58, 0x40, 0x40]);
    assert_eq!(nas.len(), 16, "no TFT, no APN-AMBR");
    erab_modify_response(&ue, &[6]);
    assert!(quiet(&sgw), "the answer waits for the UE");
    ue_esm(&ue, 6, &[0xca]);
    assert_eq!(update_bearer_response(&sgw, 0x1271), (16, vec![(6, 16)]));
    assert_eq!(ctx.bearer_find_by_id(b6).unwrap().qos.mbr.downlink, 256_000);
    assert_eq!(crate::bearer_activation::pending_count(), 0);
    release(&ue);
}

/// #641 Update half, TS 23.401 §5.4.3: a TFT-only Update Bearer Request (no
/// Bearer QoS). The MODIFY EPS BEARER CONTEXT REQUEST, with the TFT and no New
/// EPS QoS, goes in a DOWNLINK NAS TRANSPORT (no E-RAB MODIFY); the UE's ACCEPT
/// alone settles it.
#[test]
fn a_tft_only_update_goes_in_downlink_nas_transport() {
    let _guard = lock_s11();
    crate::bearer_activation::clear_for_test();
    let (sgw, route) = sgw(Gtp2XactConfig::default());
    let ue = attached(0x1272);
    let b6 = with_dedicated(&ue, 6);
    let ctx = mme_self();
    crate::s1ap_path::tap_enb_for_test(ue.enb_id);
    sgw.send_to(
        &ubr(ue.local_teid, 0x1272, 6, false, true, Some(1000)),
        route.server.local_addr(),
    )
    .unwrap();
    let nas = wait_pdu(ue.enb_id, |p| dl_nas(p).filter(|n| n.get(2) == Some(&0xc9)));
    assert_eq!(&nas[..3], &[0x62, 0x00, 0xc9]);
    assert_eq!(
        &nas[3..],
        &[0x36, 6, 0x21, 0x31, 0x00, 0x02, 0x30, 0x22],
        "the TFT only"
    );
    assert!(
        crate::s1ap_path::take_tapped_for_test(ue.enb_id)
            .iter()
            .filter_map(|p| nextgcore_s1ap_gen::decode(p).ok())
            .all(|p| erab_modify(&p).is_none()),
        "no E-RAB MODIFY for a TFT change"
    );
    ue_esm(&ue, 6, &[0xca]);
    assert_eq!(update_bearer_response(&sgw, 0x1272), (16, vec![(6, 16)]));
    assert_eq!(
        ctx.bearer_find_by_id(b6).unwrap().tft,
        vec![0x21, 0x31, 0x00, 0x02, 0x30, 0x22]
    );
    release(&ue);
}

/// #641 Update half, TS 24.301 §6.4.3.4: the UE rejects the modification. The
/// Update Bearer Response says "UE refuses" (88) and the bearer keeps its QoS.
/// An APN-AMBR change rides the request: E-RAB MODIFY with the UE-AMBR, the NAS
/// request with the APN-AMBR, and it is undone with the refusal.
#[test]
fn a_rejected_update_keeps_the_bearer_as_it_was() {
    let _guard = lock_s11();
    crate::bearer_activation::clear_for_test();
    let (sgw, route) = sgw(Gtp2XactConfig::default());
    let ue = attached(0x1273);
    let b6 = with_dedicated(&ue, 6);
    let ctx = mme_self();
    crate::s1ap_path::tap_enb_for_test(ue.enb_id);
    sgw.send_to(
        &ubr(ue.local_teid, 0x1273, 6, true, false, Some(2000)),
        route.server.local_addr(),
    )
    .unwrap();
    let (items, ambr) = wait_pdu(ue.enb_id, erab_modify);
    assert!(ambr, "the APN-AMBR change updates the UE-AMBR");
    assert!(
        items[0]
            .1
            .windows(2)
            .any(|w| w == [0x5e, 0x02] || w == [0x5e, 0x04] || w == [0x5e, 0x06]),
        "the APN-AMBR in the NAS request"
    );
    erab_modify_response(&ue, &[6]);
    ue_esm(&ue, 6, &[0xcb, 31]);
    assert_eq!(update_bearer_response(&sgw, 0x1273), (88, vec![(6, 88)]));
    assert_eq!(
        ctx.bearer_find_by_id(b6).unwrap().qos.mbr.downlink,
        128_000,
        "kept"
    );
    assert_eq!(
        ctx.sess_find_by_id(ue.sess_id).unwrap().ambr.downlink,
        1_000_000,
        "kept"
    );
    release(&ue);
}

/// #641 Update half, TS 23.401 §5.4.2.1 step 3: an ECM-IDLE UE is paged. Here
/// the paging fails: "Unable to page UE" (90). A second request is signalled once
/// the UE is ECM-CONNECTED again.
#[test]
fn an_update_for_an_idle_ue_pages_it() {
    let _guard = lock_s11();
    crate::bearer_activation::clear_for_test();
    let (sgw, route) = sgw(Gtp2XactConfig::default());
    let mme = route.server.local_addr();
    let ctx = mme_self();
    let ue = attached(0x1274);
    let _b6 = with_dedicated(&ue, 6);
    crate::s1ap_path::tap_enb_for_test(ue.enb_id);
    let complete = release_to_command(&ue, &sgw);
    crate::s1ap_handler::handle_ue_context_release_complete(ctx, ue.enb_id, &complete);
    let _ = crate::s1ap_path::take_tapped_for_test(ue.enb_id);
    sgw.send_to(&ubr(ue.local_teid, 0x1274, 6, false, true, Some(1000)), mme)
        .unwrap();
    wait_pdu(ue.enb_id, is_paging);
    assert!(quiet(&sgw), "the answer waits for the paging");
    crate::bearer_activation::on_paging_failed(ctx, ue.mme_ue_id);
    assert_eq!(update_bearer_response(&sgw, 0x1274), (90, vec![(6, 90)]));

    sgw.send_to(&ubr(ue.local_teid, 0x1275, 6, false, true, Some(1000)), mme)
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    while crate::bearer_activation::pending_count() == 0 {
        assert!(Instant::now() < deadline, "parked behind paging");
        std::thread::sleep(Duration::from_millis(5));
    }
    let new_enb_ue = ctx.enb_ue_add(ue.enb_id, 12740);
    ctx.enb_ue_associate_mme_ue(new_enb_ue, ue.mme_ue_id);
    crate::bearer_activation::on_connected(ctx, ue.mme_ue_id);
    let _ = wait_pdu(ue.enb_id, |p| dl_nas(p).filter(|n| n.get(2) == Some(&0xc9)));
    ue_esm(&ue, 6, &[0xca]);
    assert_eq!(update_bearer_response(&sgw, 0x1275), (16, vec![(6, 16)]));
    ctx.enb_ue_remove(new_enb_ue);
    release(&ue);
}

/// #641 Update half, TS 29.274 §7.2.16: an EBI the UE has no bearer for is
/// "Context not found" (64); a request without its APN-AMBR (M, Table 7.2.15-1)
/// is 70 naming it as the Offending IE.
#[test]
fn an_update_bearer_request_with_a_fault_is_refused() {
    let _guard = lock_s11();
    crate::bearer_activation::clear_for_test();
    let (sgw, route) = sgw(Gtp2XactConfig::default());
    let mme = route.server.local_addr();
    let ue = attached(0x1276);
    sgw.send_to(&ubr(ue.local_teid, 0x1276, 9, true, false, Some(1000)), mme)
        .unwrap();
    assert_eq!(update_bearer_response(&sgw, 0x1276), (64, vec![(9, 64)]));
    sgw.send_to(&ubr(ue.local_teid, 0x1277, 5, true, false, None), mme)
        .unwrap();
    let (rsp, _) = recv(&sgw, 98);
    assert_eq!(
        rsp.get_ie(Gtp2IeType::Cause as u8, 0)
            .unwrap()
            .value
            .to_vec(),
        vec![70, 0, Gtp2IeType::Ambr as u8, 0, 0, 0]
    );
    assert_eq!(crate::bearer_activation::pending_count(), 0);
    release(&ue);
}

/// #641, TS 23.401 §5.4.1 step 3: an ECM-IDLE UE is paged; when it cannot be reached
/// the request is refused "Unable to page UE". During an Attach the request waits for
/// ATTACH COMPLETE (Annex F NOTE 2). A TEID naming no UE is "Context not found".
#[test]
fn a_create_bearer_request_waits_for_paging_and_for_the_attach() {
    let _guard = lock_s11();
    crate::bearer_activation::clear_for_test();
    let (sgw, route) = sgw(Gtp2XactConfig::default());
    let mme = route.server.local_addr();
    let ctx = mme_self();

    // ECM-IDLE: paged, then the paging fails.
    let ue = attached(0x0644);
    crate::s1ap_path::tap_enb_for_test(ue.enb_id);
    let complete = release_to_command(&ue, &sgw);
    crate::s1ap_handler::handle_ue_context_release_complete(ctx, ue.enb_id, &complete);
    let _ = crate::s1ap_path::take_tapped_for_test(ue.enb_id);
    sgw.send_to(&cbr(ue.local_teid, 0x0644), mme).unwrap();
    wait_pdu(ue.enb_id, is_paging);
    assert!(quiet(&sgw), "the answer waits for the paging");
    crate::bearer_activation::on_paging_failed(ctx, ue.mme_ue_id);
    let (cause, _) = create_bearer_response(&sgw, 0x0644);
    assert_eq!(cause, 90, "Unable to page UE");
    assert!(ctx.bearer_find_by_ebi(ue.mme_ue_id, 6).is_none());
    release(&ue);

    // During the Attach: nothing is signalled until ATTACH COMPLETE.
    let ue = seed(0x0645, &[5]);
    ctx.mme_ue_pool
        .write()
        .unwrap()
        .get_mut(&ue.mme_ue_id)
        .unwrap()
        .nas_eps
        .type_ = crate::context::MmeEpsType::AttachRequest;
    crate::s1ap_path::tap_enb_for_test(ue.enb_id);
    sgw.send_to(&cbr(ue.local_teid, 0x0645), mme).unwrap();
    std::thread::sleep(Duration::from_millis(300));
    assert!(
        crate::s1ap_path::take_tapped_for_test(ue.enb_id)
            .iter()
            .filter_map(|p| nextgcore_s1ap_gen::decode(p).ok())
            .all(|p| erab_setup(&p).is_none()),
        "no E-RAB SETUP before ATTACH COMPLETE"
    );
    assert_eq!(crate::bearer_activation::pending_count(), 1);
    crate::bearer_activation::on_attach_complete(ctx, ue.mme_ue_id);
    let items = wait_pdu(ue.enb_id, erab_setup);
    assert_eq!(items[0].0, 6);
    crate::bearer_activation::clear_for_test();
    release(&ue);

    // No UE.
    sgw.send_to(&cbr(0x00FF_0641, 0x0646), mme).unwrap();
    let (rsp, _) = recv(&sgw, 96);
    assert_eq!(rsp.header.teid, Some(0));
    assert_eq!(
        Gtp2CauseIe::decode(&rsp.get_ie(Gtp2IeType::Cause as u8, 0).unwrap().value)
            .unwrap()
            .cause,
        64
    );
}

/// #891, TS 23.401 §5.3.5 step 2: a local S1 release of an ECM-CONNECTED UE
/// (here a partial RESET from its eNB, TS 36.413 §8.7.1) sends the Serving GW a
/// Release Access Bearers Request and forgets the eNB S1-U endpoints. Before,
/// the SGW kept forwarding downlink to the released eNB and never notified, so
/// the data was lost and the UE was not paged.
#[test]
fn a_local_s1_release_releases_the_access_bearers_at_the_serving_gw() {
    let _guard = lock_s11();
    let (sgw, _route) = sgw(Gtp2XactConfig::default());
    let ue = seed(0x0891, &[5]);
    let ctx = mme_self();
    let enb_ue = ctx.enb_ue_find_by_id(ue.enb_ue_id).unwrap();
    crate::s1ap_handler::handle_reset(
        ctx,
        ue.enb_id,
        &nextgcore_s1ap::Reset {
            cause: nextgcore_s1ap::Cause::RadioNetwork(
                nextgcore_s1ap::CauseRadioNetwork::Unspecified,
            ),
            reset_type: nextgcore_s1ap::ResetType::PartOfS1Interface(vec![
                nextgcore_s1ap::UeAssociatedLogicalS1Connection {
                    mme_ue_s1ap_id: Some(enb_ue.mme_ue_s1ap_id),
                    enb_ue_s1ap_id: Some(enb_ue.enb_ue_s1ap_id),
                },
            ]),
        },
    );
    let (rab, _) = recv(&sgw, 170);
    assert_eq!(rab.header.teid, Some(SGW_S11_TEID));
    let b5 = ctx
        .bearer_find_by_ebi(ue.mme_ue_id, 5)
        .and_then(|id| ctx.bearer_find_by_id(id))
        .unwrap();
    assert_eq!(b5.enb_s1u_teid, 0, "the eNB endpoint is forgotten");
    release(&ue);
}

/// #891: the S1 release procedure sends exactly one Release Access Bearers
/// Request: the UE CONTEXT RELEASE COMPLETE, which also ends in the local
/// release, finds the endpoints already cleared and sends none.
#[test]
fn an_s1_release_procedure_sends_one_release_access_bearers_request() {
    let _guard = lock_s11();
    let (sgw, _route) = sgw(Gtp2XactConfig::default());
    let ue = seed(0x0892, &[5]);
    let ctx = mme_self();
    crate::s1ap_path::tap_enb_for_test(ue.enb_id);
    let complete = release_to_command(&ue, &sgw);
    crate::s1ap_handler::handle_ue_context_release_complete(ctx, ue.enb_id, &complete);
    sgw.set_read_timeout(Some(Duration::from_millis(300)))
        .unwrap();
    let mut buf = [0u8; 4096];
    let mut again = 0;
    while let Ok((len, _)) = sgw.recv_from(&mut buf) {
        if buf[..len].get(1) == Some(&170) {
            again += 1;
        }
    }
    assert_eq!(again, 0, "no second Release Access Bearers Request");
    release(&ue);
}
