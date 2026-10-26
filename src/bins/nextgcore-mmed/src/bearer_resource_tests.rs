//! #1282: the UE's BEARER RESOURCE ALLOCATION / MODIFICATION REQUEST through the MME
//! (TS 23.401 §5.4.5, TS 24.301 §6.5.3 / §6.5.4), on a real S11 socket with a
//! stand-in Serving GW, the eNB side read through `s1ap_path`'s tap.

use crate::context::mme_self;
use crate::gtp_path::lock_s11;
use crate::idle_mode_tests::{
    attached, dl_nas, erab_setup, quiet, recv, release, sgw, wait_pdu, with_dedicated, Ue,
    DEDICATED_SGW_S1U,
};
use nextgcore_gtp::v2::xact::Gtp2XactConfig;
use nextgcore_gtp::v2::{Gtp2BearerContextIe, Gtp2Ie, Gtp2IeType, Gtp2Message};
use nextgcore_s1ap_gen::generated as g;
use std::net::UdpSocket;
use std::time::Duration;

/// A TFA "create new TFT" with one bidirectional UDP filter (TS 24.008 §10.5.6.12).
const TFA_CREATE: [u8; 6] = [0x21, 0x31, 0x00, 0x02, 0x30, 0x11];
/// A TFA "delete packet filters from existing TFT", filter 1.
const TFA_DELETE: [u8; 2] = [0xa1, 0x01];
/// Required traffic flow QoS contents: QCI 1, MBR 128 / GBR 64 kbit/s each way
/// (TS 24.301 §9.9.4.3, TS 24.008 Table 10.5.156: 0x48 = 128, 0x40 = 64).
const QOS_QCI1: [u8; 5] = [1, 0x48, 0x48, 0x40, 0x40];

fn ue_esm(ue: &Ue, plain: &[u8]) {
    let ctx = mme_self();
    let mme_ue = ctx.mme_ue_find_by_id(ue.mme_ue_id).unwrap();
    let enb_ue = ctx.enb_ue_find_by_id(mme_ue.enb_ue_id).unwrap();
    crate::nas_dispatch::handle_esm_message(ctx, &enb_ue, &mme_ue, plain);
}

/// BEARER RESOURCE ALLOCATION REQUEST (Table 8.3.8.1): header EBI 0, LBI, TFA (LV),
/// Required traffic flow QoS (LV), then PCO and Device properties.
fn bra(pti: u8, lbi: u8) -> Vec<u8> {
    let mut m = vec![0x02, pti, 0xd4, lbi];
    m.push(TFA_CREATE.len() as u8);
    m.extend_from_slice(&TFA_CREATE);
    m.push(QOS_QCI1.len() as u8);
    m.extend_from_slice(&QOS_QCI1);
    m.extend_from_slice(&[0x27, 3, 0x80, 0x00, 0x00, 0xc1]);
    m
}

/// BEARER RESOURCE MODIFICATION REQUEST (Table 8.3.10.1) for `ebi`: TFA (LV), then
/// ESM cause #36 (TV) when it is a release.
fn brm(pti: u8, ebi: u8, tfa: &[u8], release: bool) -> Vec<u8> {
    let mut m = vec![0x02, pti, 0xd6, ebi, tfa.len() as u8];
    m.extend_from_slice(tfa);
    if release {
        m.extend_from_slice(&[0x58, 36]);
    }
    m
}

fn ie(m: &Gtp2Message, t: Gtp2IeType, instance: u8) -> Option<Vec<u8>> {
    m.get_ies(t as u8)
        .into_iter()
        .find(|ie| ie.instance == instance)
        .map(|ie| ie.value.to_vec())
}

/// The Bearer Resource Command's triggered Create Bearer Request: as the PGW's
/// for the Command (TS 29.274 §7.2.3), under its number and with its PTI.
fn triggered_cbr(teid: u32, seq: u32, pti: u8) -> Vec<u8> {
    use nextgcore_gtp::v2::{Gtp2BearerQosIe, Gtp2EbiIe, Gtp2FTeidIe};
    let mut m = Gtp2Message::new(nextgcore_gtp::v2::Gtp2Header::new(95, teid, seq));
    m.add_ie(Gtp2EbiIe::new(5).to_ie(0));
    m.add_ie(Gtp2Ie::from_slice(Gtp2IeType::Pti as u8, 0, &[pti]));
    let mut bc = Gtp2BearerContextIe::new();
    bc.set_ebi(0);
    bc.add_ie(Gtp2Ie::from_slice(
        Gtp2IeType::BearerTft as u8,
        0,
        &TFA_CREATE,
    ));
    bc.set_fteid(
        0,
        &Gtp2FTeidIe::new_ipv4(1, DEDICATED_SGW_S1U, [10, 0, 0, 2]),
    );
    bc.set_fteid(1, &Gtp2FTeidIe::new_ipv4(5, 0x0bee_f0d1, [10, 0, 0, 3]));
    bc.set_bearer_qos(&Gtp2BearerQosIe::new(1, 128, 128, 64, 64));
    m.add_bearer_context(0, &bc);
    m.encode().to_vec()
}

fn is_brc(sgw: &UdpSocket) -> Gtp2Message {
    recv(sgw, crate::s11_build::message_type::BEARER_RESOURCE_COMMAND).0
}

/// The plain ESM message of the next DOWNLINK NAS TRANSPORT, which must be
/// `esm_type`. Not filtered: since #1295 no other test's PDUs reach this eNB's tap.
fn next_dl_esm(ue: &Ue, esm_type: u8) -> Vec<u8> {
    let esm = wait_pdu(ue.enb_id, dl_nas);
    assert_eq!(esm.get(2), Some(&esm_type), "the next DL NAS is {esm:02x?}");
    esm
}

fn erab_release_nas(pdu: &g::S1AP_PDU) -> Option<Vec<u8>> {
    let g::S1AP_PDU::InitiatingMessage(g::InitiatingMessage {
        value: g::InitiatingMessageValue::Id_E_RABRelease(cmd),
        ..
    }) = pdu
    else {
        return None;
    };
    cmd.protocol_i_es.0.iter().find_map(|ie| match &ie.value {
        g::E_RABReleaseCommandProtocolIEs_EntryValue::Id_NAS_PDU(nas) => {
            nas.0.get(6..).map(|p| p.to_vec())
        }
        _ => None,
    })
}

fn setup() -> (
    std::sync::MutexGuard<'static, ()>,
    UdpSocket,
    crate::gtp_path::S11TestRoute,
    Ue,
) {
    let guard = lock_s11();
    crate::bearer_activation::clear_for_test();
    crate::bearer_deactivation::clear_for_test();
    crate::bearer_resource::clear_for_test();
    let (sgw, route) = sgw(Gtp2XactConfig::default());
    let ue = attached(0x1282);
    crate::s1ap_path::tap_enb_for_test(ue.enb_id);
    (guard, sgw, route, ue)
}

/// TS 23.401 §5.4.5 steps 1-2, TS 29.274 Table 7.2.5-1: the UE's allocation request
/// goes to the Serving GW as a Bearer Resource Command under a Command number,
/// with the LBI, the PTI, the TAD (the TFA as is), the Flow QoS (QCI 1, the four
/// rates in kbit/s), no EPS Bearer ID, and the UE's PCO. Its triggered Create
/// Bearer Request runs the dedicated bearer activation with the UE's PTI
/// (§6.5.3.3). The UE's retransmission makes no second Command, before or after.
#[test]
fn an_allocation_request_goes_on_as_a_bearer_resource_command() {
    let (_guard, sgw, route, ue) = setup();
    let mme = route.server.local_addr();

    ue_esm(&ue, &bra(7, 5));
    let brc = is_brc(&sgw);
    let seq = brc.header.sequence_number;
    assert!(nextgcore_gtp::v2::is_command_sequence(seq), "{seq:#x}");
    assert_eq!(brc.header.teid, Some(crate::idle_mode_tests::SGW_S11_TEID));
    assert_eq!(ie(&brc, Gtp2IeType::Ebi, 0), Some(vec![5]), "LBI");
    assert_eq!(ie(&brc, Gtp2IeType::Pti, 0), Some(vec![7]), "PTI");
    assert_eq!(ie(&brc, Gtp2IeType::Tad, 0), Some(TFA_CREATE.to_vec()));
    assert_eq!(
        ie(&brc, Gtp2IeType::Ebi, 1),
        None,
        "no EBI for an allocation"
    );
    let flow = ie(&brc, Gtp2IeType::FlowQos, 0).expect("Flow QoS");
    assert_eq!(flow[0], 1, "QCI");
    assert_eq!(&flow[1..6], &[0, 0, 0, 0, 128], "UL MBR, kbit/s");
    assert_eq!(&flow[16..21], &[0, 0, 0, 0, 64], "DL GBR, kbit/s");
    assert_eq!(
        ie(&brc, Gtp2IeType::Pco, 0),
        Some(vec![0x80, 0x00, 0x00]),
        "the UE's PCO, copied"
    );

    ue_esm(&ue, &bra(7, 5));
    assert!(quiet(&sgw), "a retransmission while the Command is out");
    assert_eq!(crate::bearer_resource::outstanding_count(), 1);

    sgw.send_to(&triggered_cbr(ue.local_teid, seq, 7), mme)
        .unwrap();
    let items = wait_pdu(ue.enb_id, |pdu| {
        erab_setup(pdu).filter(|i| i.first().is_some_and(|(_, _, n)| n.get(8) == Some(&0xc5)))
    });
    let (erab, _, nas) = &items[0];
    assert_eq!(*erab, 6);
    assert_eq!(
        &nas[6..10],
        &[0x62, 7, 0xc5, 0x05],
        "ACTIVATE DEDICATED EPS BEARER CONTEXT REQUEST with the UE's PTI"
    );
    assert_eq!(crate::bearer_resource::outstanding_count(), 0);
    ue_esm(&ue, &bra(7, 5));
    assert!(quiet(&sgw), "a retransmission after the triggered request");
    release(&ue);
}

/// TS 24.301 §6.5.3.6 a), §7.3.1 c): a linked EBI that is no default bearer is
/// rejected #43, and a reserved PTI #81; neither reaches the Serving GW.
#[test]
fn an_allocation_request_the_mme_refuses_is_rejected_at_once() {
    let (_guard, sgw, _route, ue) = setup();
    with_dedicated(&ue, 6);

    ue_esm(&ue, &bra(8, 6));
    assert_eq!(&next_dl_esm(&ue, 0xd5)[..4], &[0x02, 8, 0xd5, 43]);
    ue_esm(&ue, &bra(9, 9));
    assert_eq!(&next_dl_esm(&ue, 0xd5)[..4], &[0x02, 9, 0xd5, 43]);
    ue_esm(&ue, &bra(0xff, 5));
    assert_eq!(&next_dl_esm(&ue, 0xd5)[..4], &[0x02, 0xff, 0xd5, 81]);
    assert!(quiet(&sgw), "no Command");
    release(&ue);
}

/// TS 24.301 §6.5.3.6 b) / §6.5.4.6 b): on a PDN connection for emergency bearer
/// services (request type "emergency", §9.9.4.14) an allocation is rejected #31 and
/// a modification #30, with no Command (#1292 review MINOR 1).
#[test]
fn a_request_on_an_emergency_pdn_connection_is_rejected() {
    let (_guard, sgw, _route, ue) = setup();
    with_dedicated(&ue, 6);
    mme_self()
        .sess_pool
        .write()
        .unwrap()
        .get_mut(&ue.sess_id)
        .unwrap()
        .ue_request_type = 4;

    ue_esm(&ue, &bra(14, 5));
    assert_eq!(&next_dl_esm(&ue, 0xd5)[..4], &[0x02, 14, 0xd5, 31]);
    ue_esm(&ue, &brm(15, 6, &TFA_DELETE, true));
    assert_eq!(&next_dl_esm(&ue, 0xd7)[..4], &[0x02, 15, 0xd7, 30]);
    assert!(quiet(&sgw), "no Command");
    release(&ue);
}

/// TS 29.274 Table 7.2.5-1 (EPS Bearer ID, instance 1) and §7.2.6, TS 23.401 §5.4.5
/// step 5: a modification request names its bearer in the Command; the PDN GW's
/// Bearer Resource Failure Indication (cause #97, "semantic error in the TAD
/// operation") rejects it with ESM cause #41 (Annex C Table C.1), under its PTI.
#[test]
fn a_failure_indication_rejects_the_modification_with_the_annex_c_cause() {
    let (_guard, sgw, route, ue) = setup();
    let mme = route.server.local_addr();
    with_dedicated(&ue, 6);

    ue_esm(&ue, &brm(11, 6, &[0x61, 0x01], false));
    let brc = is_brc(&sgw);
    assert_eq!(
        ie(&brc, Gtp2IeType::Ebi, 0),
        Some(vec![5]),
        "the bearer's LBI"
    );
    assert_eq!(ie(&brc, Gtp2IeType::Ebi, 1), Some(vec![6]), "its EBI");
    assert_eq!(
        ie(&brc, Gtp2IeType::FlowQos, 0),
        None,
        "no QoS was asked for"
    );

    let mut fi = Gtp2Message::new(nextgcore_gtp::v2::Gtp2Header::new(
        69,
        ue.local_teid,
        brc.header.sequence_number,
    ));
    fi.add_ie(Gtp2Ie::from_slice(Gtp2IeType::Cause as u8, 0, &[97, 0]));
    fi.add_ie(Gtp2Ie::from_slice(Gtp2IeType::Ebi as u8, 0, &[5]));
    fi.add_ie(Gtp2Ie::from_slice(Gtp2IeType::Pti as u8, 0, &[11]));
    sgw.send_to(&fi.encode(), mme).unwrap();
    assert_eq!(
        &next_dl_esm(&ue, 0xd7)[..4],
        &[0x02, 11, 0xd7, 41],
        "BEARER RESOURCE MODIFICATION REJECT, PTI 11, #41"
    );
    assert_eq!(crate::bearer_resource::outstanding_count(), 0);
    release(&ue);
}

/// TS 24.301 §6.5.4.3 iii), TS 29.274 Table 7.2.9.2-1: a release the PDN GW carries
/// out with a Delete Bearer Request (the Command's triggered message, with the
/// PTI) reaches the UE as DEACTIVATE EPS BEARER CONTEXT REQUEST with that PTI, so
/// it stops T3481.
#[test]
fn a_release_request_is_deactivated_with_the_ues_pti() {
    let (_guard, sgw, route, ue) = setup();
    let mme = route.server.local_addr();
    with_dedicated(&ue, 6);

    ue_esm(&ue, &brm(12, 6, &TFA_DELETE, true));
    let brc = is_brc(&sgw);
    assert_eq!(ie(&brc, Gtp2IeType::Tad, 0), Some(TFA_DELETE.to_vec()));
    let mut dbr = Gtp2Message::new(nextgcore_gtp::v2::Gtp2Header::new(
        99,
        ue.local_teid,
        brc.header.sequence_number,
    ));
    dbr.add_ie(Gtp2Ie::from_slice(Gtp2IeType::Ebi as u8, 1, &[6]));
    dbr.add_ie(Gtp2Ie::from_slice(Gtp2IeType::Pti as u8, 0, &[12]));
    sgw.send_to(&dbr.encode(), mme).unwrap();
    let nas = wait_pdu(ue.enb_id, |pdu| {
        erab_release_nas(pdu).filter(|n| n.get(2) == Some(&0xcd))
    });
    assert_eq!(
        &nas[..3],
        &[0x62, 12, 0xcd],
        "DEACTIVATE EPS BEARER CONTEXT REQUEST for EBI 6 with PTI 12"
    );
    assert_eq!(crate::bearer_resource::outstanding_count(), 0);
    release(&ue);
}

/// TS 29.274 §7.6, Annex C Table C.1 (#100 -> #34): a Command the Serving GW never
/// answers is rejected to the UE once N3 is spent.
#[test]
fn an_unanswered_command_is_rejected_after_n3() {
    let guard = lock_s11();
    crate::bearer_resource::clear_for_test();
    let config = Gtp2XactConfig {
        t3_response: Duration::from_millis(50),
        n3_requests: 1,
        ..Gtp2XactConfig::default()
    };
    let (sgw, _route) = sgw(config);
    let ue = attached(0x1283);
    crate::s1ap_path::tap_enb_for_test(ue.enb_id);

    ue_esm(&ue, &bra(13, 5));
    is_brc(&sgw);
    assert_eq!(&next_dl_esm(&ue, 0xd5)[..4], &[0x02, 13, 0xd5, 34]);
    assert_eq!(crate::bearer_resource::outstanding_count(), 0);
    release(&ue);
    drop(guard);
}
