//! #1103: a UE-initiated detach, and the implicit detach of a context a
//! re-attach replaces, delete the UE's PDN connections at the gateways (TS
//! 23.401 §5.3.8.2.1 step 2, §5.3.2.1 step 4): a Delete Session Request per PDN
//! connection, Linked EPS Bearer ID the default bearer, Operation Indication set
//! (TS 29.274 §7.2.9.1). Driven through `nas_eps_handle_uplink` against the
//! global context with a real S11 socket and a stand-in Serving GW, as
//! `idle_mode_tests` is.

use crate::context::mme_self;
use crate::gtp_path::lock_s11;
use crate::idle_mode_tests::{
    add_pdn, is_release_command, recv, release, seed, sgw, wait_pdu, Ue, KNAS_INT, SGW_S11_TEID,
};
use nextgcore_gtp::v2::xact::Gtp2XactConfig;
use nextgcore_gtp::v2::{Gtp2CauseIe, Gtp2IeType, Gtp2IndicationIe, Gtp2Message};
use nextgcore_s1ap_gen::generated as g;
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

const CREATE_SESSION_REQUEST: u8 = 32;
const DELETE_SESSION_REQUEST: u8 = 36;
const DELETE_SESSION_RESPONSE: u8 = 37;
const DETACH_ACCEPT: u8 = 0x46;

/// A DETACH REQUEST (TS 24.301 §8.2.11.1, EPS detach) with the UE's GUTI,
/// integrity protected under EIA2 at uplink COUNT `count` (sequence number
/// its low octet).
fn detach_request(switch_off: bool, count: u32) -> Vec<u8> {
    let detach_type = 0x01 | if switch_off { 0x08 } else { 0 };
    let plain = [
        0x07u8,
        0x45,
        detach_type,
        0x0b,
        0xf6,
        0x99,
        0xf9,
        0x07,
        0x00,
        0x02,
        0x01,
        0x00,
        0x00,
        0x09,
        0x61,
    ];
    let mut signed = vec![count as u8];
    signed.extend_from_slice(&plain);
    let mac = crate::nas_security::nas_mac_calculate(2, &KNAS_INT, count, 0, 0, &signed);
    let mut pdu = vec![0x17u8];
    pdu.extend_from_slice(&mac);
    pdu.extend_from_slice(&signed);
    pdu
}

fn send_detach(ue: &Ue, switch_off: bool, count: u32) {
    crate::nas_dispatch::nas_eps_handle_uplink(
        mme_self(),
        crate::nas_dispatch::UplinkNas {
            enb_ue_id: ue.enb_ue_id,
            nas_pdu: &detach_request(switch_off, count),
            s_tmsi: None,
        },
    );
}

/// What a Delete Session Request says: (header TEID, LBI, OI).
fn delete_session(msg: &Gtp2Message) -> (Option<u32>, u8, bool) {
    let lbi = msg.get_ie(Gtp2IeType::Ebi as u8, 0).expect("LBI").value[0];
    let indication = msg
        .get_ie(Gtp2IeType::Indication as u8, 0)
        .expect("an Indication IE");
    let oi = Gtp2IndicationIe::decode(&indication.value).unwrap().oi;
    (msg.header.teid, lbi, oi)
}

/// Read `n` Delete Session Requests off the stand-in Serving GW.
fn delete_sessions(sgw: &UdpSocket, n: usize) -> Vec<(Gtp2Message, SocketAddr)> {
    (0..n).map(|_| recv(sgw, DELETE_SESSION_REQUEST)).collect()
}

fn answer(sgw: &UdpSocket, ue: &Ue, req: &Gtp2Message, from: SocketAddr) {
    let mut rsp = Gtp2Message::new(nextgcore_gtp::v2::Gtp2Header::new(
        DELETE_SESSION_RESPONSE,
        ue.local_teid,
        req.header.sequence_number,
    ));
    rsp.add_ie(Gtp2CauseIe::new(16).to_ie(0));
    sgw.send_to(&rsp.encode(), from).unwrap();
}

/// Whether `pdu` is a DOWNLINK NAS TRANSPORT carrying a DETACH ACCEPT.
fn is_detach_accept(pdu: &g::S1AP_PDU) -> Option<()> {
    let g::S1AP_PDU::InitiatingMessage(g::InitiatingMessage {
        value: g::InitiatingMessageValue::Id_downlinkNASTransport(dl),
        ..
    }) = pdu
    else {
        return None;
    };
    dl.protocol_i_es.0.iter().find_map(|ie| match &ie.value {
        g::DownlinkNASTransportProtocolIEs_EntryValue::Id_NAS_PDU(nas) => {
            // Security protected: the plain message type follows the 6-octet
            // security header and the protocol discriminator.
            (nas.0.get(7) == Some(&DETACH_ACCEPT)).then_some(())
        }
        _ => None,
    })
}

/// What reached the eNB so far: (DETACH ACCEPTs, UE CONTEXT RELEASE COMMANDs).
fn tapped(enb_id: u64) -> (usize, usize) {
    let pdus = crate::s1ap_path::take_tapped_for_test(enb_id);
    let decoded: Vec<_> = pdus
        .iter()
        .filter_map(|p| nextgcore_s1ap_gen::decode(p).ok())
        .collect();
    (
        decoded
            .iter()
            .filter(|p| is_detach_accept(p).is_some())
            .count(),
        decoded
            .iter()
            .filter(|p| is_release_command(p).is_some())
            .count(),
    )
}

fn cleanup(ue: &Ue) {
    mme_self().enb_ue_remove(ue.enb_ue_id);
    release(ue);
}

/// TS 23.401 §5.3.8.2.1: a Delete Session Request per PDN connection, LBI the
/// default bearer and OI set; the DETACH ACCEPT and the S1 release wait for the
/// last response. Before #1103 the MME accepted and released at once, and sent
/// nothing to the Serving GW.
#[test]
fn a_ue_initiated_detach_deletes_every_pdn_connection_then_accepts() {
    let _guard = lock_s11();
    let (sgw, _route) = sgw(Gtp2XactConfig::default());
    let ue = seed(0x1103, &[5, 6]);
    add_pdn(&ue, 7);
    let ctx = mme_self();
    crate::s1ap_path::tap_enb_for_test(ue.enb_id);
    let _ = crate::s1ap_path::take_tapped_for_test(ue.enb_id);
    let sent0 = crate::gtp_path::DELETE_SESSION_REQUESTS_TOTAL.load(Ordering::Relaxed);
    let accepted0 = crate::gtp_path::DELETE_SESSION_ACCEPTED_TOTAL.load(Ordering::Relaxed);

    send_detach(&ue, false, 0);

    let reqs = delete_sessions(&sgw, 2);
    let mut seen: Vec<_> = reqs.iter().map(|(m, _)| delete_session(m)).collect();
    seen.sort();
    assert_eq!(
        seen,
        vec![(Some(SGW_S11_TEID), 5, true), (Some(SGW_S11_TEID), 7, true)],
        "one per PDN connection, to the Serving GW's TEID, LBI the default bearer, OI set"
    );
    assert!(
        crate::gtp_path::DELETE_SESSION_REQUESTS_TOTAL.load(Ordering::Relaxed) >= sent0 + 2,
        "counted"
    );
    let mme_ue = ctx.mme_ue_find_by_id(ue.mme_ue_id).expect("waits");
    assert!(mme_ue.sess_list.is_empty(), "released locally at once");
    assert_eq!(tapped(ue.enb_id), (0, 0), "nothing to the UE yet");

    // #1106 review MINOR 1: the UE's T3421 retransmission is the same detach,
    // and keeps waiting rather than completing ahead of the Serving GW.
    send_detach(&ue, false, 1);
    assert!(ctx.mme_ue_find_by_id(ue.mme_ue_id).is_some(), "still waits");
    assert_eq!(
        tapped(ue.enb_id),
        (0, 0),
        "nothing to the UE on the retransmission"
    );

    // The first answer: one still outstanding.
    answer(&sgw, &ue, &reqs[0].0, reqs[0].1);
    std::thread::sleep(Duration::from_millis(200));
    assert!(ctx.mme_ue_find_by_id(ue.mme_ue_id).is_some());
    assert_eq!(tapped(ue.enb_id), (0, 0), "still waiting on the second");

    // The last one completes the detach.
    answer(&sgw, &ue, &reqs[1].0, reqs[1].1);
    wait_pdu(ue.enb_id, is_detach_accept);
    let deadline = Instant::now() + Duration::from_secs(5);
    while ctx.mme_ue_find_by_id(ue.mme_ue_id).is_some() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(ctx.mme_ue_find_by_id(ue.mme_ue_id).is_none(), "removed");
    assert_eq!(
        ctx.enb_ue_find_by_id(ue.enb_ue_id)
            .unwrap()
            .ue_ctx_rel_action,
        crate::context::UeCtxRelAction::UeContextRemove,
        "S1 released"
    );
    assert!(
        crate::gtp_path::DELETE_SESSION_ACCEPTED_TOTAL.load(Ordering::Relaxed) >= accepted0 + 2
    );
    cleanup(&ue);
}

/// TS 24.301 §5.5.2.2.2: a switch-off detach deletes the PDN connections the
/// same way but gets no DETACH ACCEPT.
#[test]
fn a_switch_off_detach_deletes_the_pdn_connection_without_a_detach_accept() {
    let _guard = lock_s11();
    let (sgw, _route) = sgw(Gtp2XactConfig::default());
    let ue = seed(0x1104, &[5]);
    let ctx = mme_self();
    crate::s1ap_path::tap_enb_for_test(ue.enb_id);
    let _ = crate::s1ap_path::take_tapped_for_test(ue.enb_id);

    send_detach(&ue, true, 0);

    let (req, from) = recv(&sgw, DELETE_SESSION_REQUEST);
    assert_eq!(delete_session(&req), (Some(SGW_S11_TEID), 5, true));
    answer(&sgw, &ue, &req, from);
    let deadline = Instant::now() + Duration::from_secs(5);
    while ctx.mme_ue_find_by_id(ue.mme_ue_id).is_some() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(ctx.mme_ue_find_by_id(ue.mme_ue_id).is_none(), "removed");
    assert_eq!(
        ctx.enb_ue_find_by_id(ue.enb_ue_id)
            .unwrap()
            .ue_ctx_rel_action,
        crate::context::UeCtxRelAction::UeContextRemove,
        "S1 released"
    );
    assert_eq!(
        tapped(ue.enb_id).0,
        0,
        "no DETACH ACCEPT to a switched-off UE"
    );
    cleanup(&ue);
}

/// A Serving GW that never answers does not hold the detach up: when the
/// request's retransmissions run out (TS 29.274 §7.6) the detach completes.
#[test]
fn an_unanswered_delete_session_request_does_not_block_the_detach() {
    let _guard = lock_s11();
    let (sgw, _route) = sgw(Gtp2XactConfig {
        t3_response: Duration::from_millis(100),
        n3_requests: 1,
        ..Gtp2XactConfig::default()
    });
    let ue = seed(0x1105, &[5]);
    let ctx = mme_self();
    crate::s1ap_path::tap_enb_for_test(ue.enb_id);
    let _ = crate::s1ap_path::take_tapped_for_test(ue.enb_id);
    let timeouts0 = crate::gtp_path::DELETE_SESSION_TIMEOUTS_TOTAL.load(Ordering::Relaxed);

    send_detach(&ue, false, 0);

    let (req, _) = recv(&sgw, DELETE_SESSION_REQUEST);
    assert_eq!(delete_session(&req), (Some(SGW_S11_TEID), 5, true));
    wait_pdu(ue.enb_id, is_detach_accept);
    assert!(ctx.mme_ue_find_by_id(ue.mme_ue_id).is_none(), "removed");
    assert!(
        crate::gtp_path::DELETE_SESSION_TIMEOUTS_TOTAL.load(Ordering::Relaxed) > timeouts0,
        "the timeout is counted"
    );
    cleanup(&ue);
}

/// The 15-digit `imsi` as an EPS mobile identity (TS 24.301 §9.9.3.12).
fn imsi_identity(imsi: &str) -> Vec<u8> {
    let d: Vec<u8> = imsi.bytes().map(|b| b - b'0').collect();
    let mut out = vec![(d[0] << 4) | 0x09];
    out.extend(d[1..].chunks(2).map(|c| (c[1] << 4) | c[0]));
    out
}

/// TS 23.401 §5.3.2.1 step 4 / TS 24.301 §5.5.1.2.4: an ATTACH REQUEST from a
/// UE whose old context the MME still holds deletes that context's PDN
/// connections at the gateways. Before #1103 every re-attach leaked one.
#[test]
fn a_re_attach_deletes_the_replaced_contexts_pdn_connections() {
    let _guard = lock_s11();
    let (sgw, _route) = sgw(Gtp2XactConfig::default());
    let ue = seed(0x1106, &[5]);
    add_pdn(&ue, 6);
    let ctx = mme_self();
    let imsi = format!("99970001106{:04}", ue.mme_ue_id % 10_000);
    ctx.mme_ue_set_imsi(ue.mme_ue_id, &imsi);

    let new_conn = ctx.enb_ue_add(ue.enb_id, 1106);
    let identity = imsi_identity(&imsi);
    let esm = [0x02u8, 0x01, 0xd0, 0x11];
    let mut attach = vec![0x07u8, 0x41, 0x71, identity.len() as u8];
    attach.extend_from_slice(&identity);
    attach.extend_from_slice(&[0x02, 0xf0, 0xf0]);
    attach.extend_from_slice(&(esm.len() as u16).to_be_bytes());
    attach.extend_from_slice(&esm);
    crate::nas_dispatch::nas_eps_handle_uplink(
        ctx,
        crate::nas_dispatch::UplinkNas {
            enb_ue_id: new_conn,
            nas_pdu: &attach,
            s_tmsi: None,
        },
    );

    let mut seen: Vec<_> = delete_sessions(&sgw, 2)
        .iter()
        .map(|(m, _)| delete_session(m))
        .collect();
    seen.sort();
    assert_eq!(
        seen,
        vec![(Some(SGW_S11_TEID), 5, true), (Some(SGW_S11_TEID), 6, true)]
    );
    assert!(ctx.mme_ue_find_by_id(ue.mme_ue_id).is_none(), "replaced");
    assert!(
        ctx.sess_find_by_id(ue.sess_id).is_none(),
        "its sessions do not linger locally"
    );
    let fresh = ctx.mme_ue_find_by_imsi(&imsi).expect("the new context");
    assert_ne!(fresh, ue.mme_ue_id);
    ctx.mme_ue_remove(fresh);
    ctx.enb_ue_remove(new_conn);
    cleanup(&ue);
}

/// #1106 review MINOR 2: the new attach's Create Session Request is held until
/// the Delete Session Requests of the context it replaced are answered. Sent
/// ahead of them, a lost one retransmitted after it could delete the new
/// session at a Serving GW that finds the UE by IMSI.
#[test]
fn a_re_attach_holds_its_create_session_until_the_old_deletions_settle() {
    let _guard = lock_s11();
    let (sgw, _route) = sgw(Gtp2XactConfig::default());
    let stale = seed(0x1107, &[5]);
    let fresh = seed(0x1108, &[5]);
    let ctx = mme_self();
    let imsi = format!("99970001107{:04}", stale.mme_ue_id % 10_000);
    for id in [stale.mme_ue_id, fresh.mme_ue_id] {
        ctx.mme_ue_pool
            .write()
            .unwrap()
            .get_mut(&id)
            .unwrap()
            .imsi_bcd = imsi.clone();
    }

    let sent = crate::gtp_path::send_delete_all_sessions_for_replaced(ctx, stale.mme_ue_id, &imsi)
        .expect("sent");
    assert_eq!(sent.len(), 1);
    let (req, from) = recv(&sgw, DELETE_SESSION_REQUEST);
    assert_eq!(delete_session(&req), (Some(SGW_S11_TEID), 5, true));
    assert!(
        crate::gtp_path::defer_create_while_replaced(
            &imsi,
            fresh.enb_ue_id,
            fresh.sess_id,
            crate::s11_build::GtpCreateAction::AttachRequest,
        ),
        "held"
    );
    sgw.set_read_timeout(Some(Duration::from_millis(300)))
        .unwrap();
    let mut buf = [0u8; 4096];
    assert!(
        sgw.recv_from(&mut buf).is_err(),
        "no Create Session Request yet"
    );
    sgw.set_read_timeout(Some(Duration::from_secs(3))).unwrap();

    answer(&sgw, &stale, &req, from);
    let (csr, _) = recv(&sgw, CREATE_SESSION_REQUEST);
    assert_eq!(
        csr.header.message_type, CREATE_SESSION_REQUEST,
        "sent once settled"
    );
    assert!(
        !crate::gtp_path::defer_create_while_replaced(
            &imsi,
            fresh.enb_ue_id,
            fresh.sess_id,
            crate::s11_build::GtpCreateAction::AttachRequest,
        ),
        "nothing outstanding any more"
    );
    cleanup(&stale);
    cleanup(&fresh);
}

/// #1106 review MINOR 3: removing a detaching context, by whatever path, drops
/// the Delete Session records its detach waited on.
#[test]
fn removing_a_detaching_context_drops_its_pending_deletes() {
    let _guard = lock_s11();
    let (sgw, _route) = sgw(Gtp2XactConfig::default());
    let ue = seed(0x1109, &[5]);
    let ctx = mme_self();
    send_detach(&ue, false, 0);
    let _ = recv(&sgw, DELETE_SESSION_REQUEST);
    assert!(crate::gtp_path::detach_deletes_outstanding(ue.mme_ue_id));
    ctx.mme_ue_remove(ue.mme_ue_id);
    assert!(!crate::gtp_path::detach_deletes_outstanding(ue.mme_ue_id));
    cleanup(&ue);
}
