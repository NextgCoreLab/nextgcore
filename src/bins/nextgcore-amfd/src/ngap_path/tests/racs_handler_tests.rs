//! #746: a UE radio capability ID update never replaces the NAS procedure in
//! flight (TS 24.501 §5.4.4.6). Driven through the real handlers, with the NGAP
//! egress captured.

use super::handler_tests::{
    decode_sent, dl_nas_message_type, secured_registered_ue, ue_protect, uplink_nas_transport,
    Sent, ASSOC,
};
use super::*;

/// PLMN-assigned, Version ID 05 (TS 23.003 §29.2), as `racs/tests.rs` uses.
const ID: [u8; 7] = [0x01, 0x05, 0x00, 0x00, 0x00, 0x00, 0x10];

/// The NGAP PDU a pending retransmission resends, recognisable on the wire.
const PENDING_PDU: [u8; 4] = [0xDE, 0xAD, 0x07, 0x46];

/// A registered RACS UE whose UCMF-assigned ID the UE does not know yet, with
/// `pending` (when given) in its retransmission slot.
fn racs_ue_with_pending(server: &mut NgapServer, ue: u64, ran: u32, pending: Option<NasProcTimer>) {
    secured_registered_ue(server, ue, ran);
    server.ue_auth_state.with_mut(ue, |s| {
        s.amf_ue.racs_supported = true;
        s.amf_ue.ue_radio_capability_id = Some(ID.to_vec());
        s.amf_ue.ue_radio_capability_id_known_to_ue = false;
        s.retx = pending.map(|timer| NasRetx {
            timer,
            deadline: Instant::now() + Duration::from_secs(6),
            retries: 0,
            ngap_pdu: PENDING_PDU.to_vec(),
        });
    });
}

/// `(pending timer, its PDU, whether the UE has been sent the ID)`.
fn slot(server: &NgapServer, ue: u64) -> (Option<NasProcTimer>, Option<Vec<u8>>, bool) {
    let s = server.ue_auth_state.get(ue).expect("UE held");
    (
        s.retx.as_ref().map(|r| r.timer),
        s.retx.as_ref().map(|r| r.ngap_pdu.clone()),
        s.amf_ue.ue_radio_capability_id_known_to_ue,
    )
}

/// The CONFIGURATION UPDATE COMMANDs among `sent`, as their NAS PDUs.
fn configuration_update_commands(sent: Vec<(u64, Vec<u8>)>) -> Vec<Vec<u8>> {
    sent.into_iter()
        .filter_map(|(_, pdu)| match decode_sent(&pdu) {
            Sent::DownlinkNas { nas_pdu, .. }
                if dl_nas_message_type(&nas_pdu)
                    == Some(message_type::CONFIGURATION_UPDATE_COMMAND) =>
            {
                Some(nas_pdu)
            }
            _ => None,
        })
        .collect()
}

/// Whether a (NEA0) protected CUC carries the UE radio capability ID IE
/// (IEI 0x67, TS 24.501 §8.2.19) with [`ID`].
fn carries_the_id(nas: &[u8]) -> bool {
    let mut ie = vec![0x67, ID.len() as u8];
    ie.extend_from_slice(&ID);
    nas.windows(ie.len()).any(|w| w == ie.as_slice())
}

/// The issue's first trigger: a mobility registration is waiting for its
/// Registration Complete (T3550) when the UCMF assigns an ID. The command waits,
/// T3550 and its Registration Accept stay in the slot, and the Registration
/// Complete delivers the ID with T3555.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_id_assigned_during_a_registration_waits_for_the_registration_complete() {
    let mut server = capturing_ngap_server().await;
    let (ue, ran) = (7_746_001u64, 46);
    racs_ue_with_pending(&mut server, ue, ran, Some(NasProcTimer::T3550));

    server
        .send_racs_configuration_update(ASSOC, ue, ran)
        .await
        .expect("handled");

    assert!(
        take_sent_ngap(&mut server).is_empty(),
        "nothing is sent while T3550 runs"
    );
    assert_eq!(
        slot(&server, ue),
        (Some(NasProcTimer::T3550), Some(PENDING_PDU.to_vec()), false),
        "T3550 keeps the Registration Accept, and the ID is still to be delivered"
    );

    let complete = ue_protect(&[0x7E, 0x00, message_type::REGISTRATION_COMPLETE], 0);
    server
        .handle_uplink_nas_transport(ASSOC, &uplink_nas_transport(ue, ran, &complete))
        .await
        .expect("Registration Complete handled");

    let cucs = configuration_update_commands(take_sent_ngap(&mut server));
    assert_eq!(cucs.len(), 1, "the deferred command goes out once");
    assert!(carries_the_id(&cucs[0]), "{:02x?}", cucs[0]);
    let (timer, _, known) = slot(&server, ue);
    assert_eq!(timer, Some(NasProcTimer::T3555));
    assert!(known);
}

/// The issue's second trigger: a network-initiated deregistration (T3522) is
/// pending. The configuration update is not started (TS 24.501 §5.4.4.6), so
/// T3522's retransmission and its exhaustion teardown stay armed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_pending_deregistration_is_not_replaced() {
    let mut server = capturing_ngap_server().await;
    let (ue, ran) = (7_746_002u64, 47);
    racs_ue_with_pending(&mut server, ue, ran, Some(NasProcTimer::T3522));

    server
        .send_racs_configuration_update(ASSOC, ue, ran)
        .await
        .expect("handled");

    assert!(take_sent_ngap(&mut server).is_empty());
    assert_eq!(
        slot(&server, ue),
        (Some(NasProcTimer::T3522), Some(PENDING_PDU.to_vec()), false)
    );
}

/// A configuration update already in flight (a 5G-GUTI reallocation, T3555):
/// the ID waits for its Configuration Update Complete, then goes in a command of
/// its own.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_id_waits_for_the_configuration_update_in_flight() {
    let mut server = capturing_ngap_server().await;
    let (ue, ran) = (7_746_003u64, 48);
    racs_ue_with_pending(&mut server, ue, ran, Some(NasProcTimer::T3555));

    server
        .send_racs_configuration_update(ASSOC, ue, ran)
        .await
        .expect("handled");
    assert!(take_sent_ngap(&mut server).is_empty());
    assert_eq!(
        slot(&server, ue),
        (Some(NasProcTimer::T3555), Some(PENDING_PDU.to_vec()), false)
    );

    let complete = ue_protect(
        &[0x7E, 0x00, message_type::CONFIGURATION_UPDATE_COMPLETE],
        0,
    );
    server
        .handle_uplink_nas_transport(ASSOC, &uplink_nas_transport(ue, ran, &complete))
        .await
        .expect("Configuration Update Complete handled");

    let cucs = configuration_update_commands(take_sent_ngap(&mut server));
    assert_eq!(cucs.len(), 1);
    assert!(carries_the_id(&cucs[0]), "{:02x?}", cucs[0]);
    let (timer, pdu, known) = slot(&server, ue);
    assert_eq!(timer, Some(NasProcTimer::T3555));
    assert_ne!(
        pdu,
        Some(PENDING_PDU.to_vec()),
        "a new command is supervised"
    );
    assert!(known);
}

/// With nothing pending the command goes out at once, as before.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn with_nothing_pending_the_id_goes_at_once() {
    let mut server = capturing_ngap_server().await;
    let (ue, ran) = (7_746_004u64, 49);
    racs_ue_with_pending(&mut server, ue, ran, None);

    server
        .send_racs_configuration_update(ASSOC, ue, ran)
        .await
        .expect("handled");

    let cucs = configuration_update_commands(take_sent_ngap(&mut server));
    assert_eq!(cucs.len(), 1);
    assert!(carries_the_id(&cucs[0]));
    assert_eq!(slot(&server, ue).0, Some(NasProcTimer::T3555));
}
