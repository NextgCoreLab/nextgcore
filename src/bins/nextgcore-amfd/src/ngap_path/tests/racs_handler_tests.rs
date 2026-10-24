//! #746: a UE radio capability ID update never replaces the NAS procedure in
//! flight (TS 24.501 §5.4.4.6). Driven through the real handlers, with the NGAP
//! egress captured.

use super::handler_tests::{
    decode_sent, dl_nas_message_type, secured_registered_ue, ue_protect, uplink_nas_transport,
    Sent, ASSOC,
};
use super::racs_mapping_tests::UcmfEnvGuard;
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
    let _racs = crate::racs::tests::guard();
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
    let _racs = crate::racs::tests::guard();
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
    let _racs = crate::racs::tests::guard();
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
    let _racs = crate::racs::tests::guard();
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

/// The ID the stand-in UCMF assigns: PLMN-assigned, Version ID 06.
const NEW_ID: [u8; 7] = [0x01, 0x06, 0x00, 0x00, 0x00, 0x00, 0x30];
/// A PEI whose TAC is `35693803`.
const PEI: &str = "imeisv-3569380356438091";

/// A stand-in UCMF answering every Assign with [`NEW_ID`], recording the TACs
/// it was asked for. Keep the server alive.
async fn assigning_ucmf() -> (
    nextgcore_sbi::server::SbiServer,
    u16,
    std::sync::Arc<std::sync::Mutex<Vec<String>>>,
) {
    ucmf_answering(|_| Some(NEW_ID.to_vec())).await
}

/// A stand-in UCMF whose `n`th Assign (from 0) is answered with `answer(n)`'s
/// ID, or 500 for `None`. Records the TACs it was asked for.
async fn ucmf_answering(
    answer: fn(usize) -> Option<Vec<u8>>,
) -> (
    nextgcore_sbi::server::SbiServer,
    u16,
    std::sync::Arc<std::sync::Mutex<Vec<String>>>,
) {
    use nextgcore_sbi::message::{SbiRequest as SReq, SbiResponse as SResp};
    nextgcore_sbi::security::set_sbi_profile_override(nextgcore_sbi::security::SbiProfile::Dev);
    let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let sink = std::sync::Arc::clone(&seen);
    let (listener, addr) = nextgcore_sbi::test_support::bound_listener().into_parts();
    let server = nextgcore_sbi::server::SbiServer::on_listener(
        nextgcore_sbi::server::SbiServerConfig::new(addr),
        listener,
    );
    server
        .start(move |req: SReq| {
            let sink = std::sync::Arc::clone(&sink);
            async move {
                if !req.header.uri.ends_with("/nucmf-uecm/v1/dic-entries") {
                    return SResp::with_status(404);
                }
                let tac = req
                    .http
                    .content
                    .as_deref()
                    .and_then(|c| serde_json::from_str::<serde_json::Value>(c).ok())
                    .and_then(|j| j["typeAllocationCode"].as_str().map(str::to_string))
                    .unwrap_or_default();
                let n = {
                    let mut seen = sink.lock().expect("sink");
                    seen.push(tac);
                    seen.len() - 1
                };
                let Some(id) = answer(n) else {
                    return SResp::with_status(500);
                };
                let body = serde_json::json!({
                    "plmnAssiUeRadioCapId": crate::racs::to_nucmf(&id),
                })
                .to_string();
                SResp::with_status(201).with_body(body, "application/json")
            }
        })
        .await
        .expect("stand-in UCMF starts");
    for _ in 0..200 {
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    (server, addr.port(), seen)
}

/// A registered RACS UE holding [`ID`], which it knows, with a stored
/// capability and [`PEI`]; CM-IDLE when `idle`.
fn racs_ue_holding_id(server: &mut NgapServer, ue: u64, ran: u32, idle: bool) {
    secured_registered_ue(server, ue, ran);
    server.ue_auth_state.with_mut(ue, |s| {
        s.amf_ue.racs_supported = true;
        s.amf_ue.ue_radio_capability_id = Some(ID.to_vec());
        s.amf_ue.ue_radio_capability_id_known_to_ue = true;
        s.amf_ue.ue_radio_capability = vec![0xC0, 0xFF, 0xEE];
        s.amf_ue.pei = Some(PEI.to_string());
        s.cm_idle = idle;
    });
}

/// Whether a protected CUC carries the UE radio capability ID IE with [`NEW_ID`].
fn carries_the_new_id(nas: &[u8]) -> bool {
    let mut ie = vec![0x67, NEW_ID.len() as u8];
    ie.extend_from_slice(&NEW_ID);
    nas.windows(ie.len()).any(|w| w == ie.as_slice())
}

/// Run the NGAP task's part: notice the retirement, settle the Assigns, apply.
async fn reassign(server: &mut NgapServer) {
    server.process_racs_reassignments();
    server.sbi_offload.settle().await;
    server.process_sbi_outcomes().await;
}

/// #748, first trigger. The UCMF moves to a new Version ID. A CM-CONNECTED UE
/// holding an ID of the old one is assigned a new ID (Assign under its PEI's
/// TAC) and gets it in a CONFIGURATION UPDATE COMMAND, supervised by T3555
/// (TS 23.501 §5.4.4.1a).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_new_version_id_reassigns_the_id_by_a_configuration_update() {
    let _racs = crate::racs::tests::guard();
    let (_ucmf, port, assigns) = assigning_ucmf().await;
    let _env = UcmfEnvGuard::acquire(port).await;
    let mut server = capturing_ngap_server().await;
    let (ue, ran) = (7_748_001u64, 51);
    racs_ue_holding_id(&mut server, ue, ran, false);

    crate::racs::apply_notification(&serde_json::json!({
        "eventType": "NEW_VERSION_ID_OF_PLMN_ASSIGNED_IDs",
        "versionId": 6,
    }));
    reassign(&mut server).await;

    assert_eq!(assigns.lock().expect("assigns").clone(), vec!["35693803"]);
    let cucs = configuration_update_commands(take_sent_ngap(&mut server));
    assert_eq!(cucs.len(), 1, "one CONFIGURATION UPDATE COMMAND");
    assert!(carries_the_new_id(&cucs[0]), "{:02x?}", cucs[0]);
    let s = server.ue_auth_state.get(ue).expect("UE held");
    assert_eq!(
        s.amf_ue.ue_radio_capability_id.as_deref(),
        Some(&NEW_ID[..])
    );
    let (timer, _, known) = slot(&server, ue);
    assert_eq!(timer, Some(NasProcTimer::T3555));
    assert!(known, "the UE is now sent the new ID");
    server.forget_ue(ue);
}

/// #748, second trigger. A UCMF deletes by TAC. The ID the UE holds is not in
/// the AMF's cache, so only the UE's PEI ties it to the TAC: it is retired, and
/// the UE re-assigned.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_deletion_by_tac_reassigns_a_ue_held_id() {
    let _racs = crate::racs::tests::guard();
    let (_ucmf, port, assigns) = assigning_ucmf().await;
    let _env = UcmfEnvGuard::acquire(port).await;
    let mut server = capturing_ngap_server().await;
    let (ue, ran) = (7_748_002u64, 52);
    racs_ue_holding_id(&mut server, ue, ran, false);

    crate::racs::apply_notification(&serde_json::json!({
        "eventType": "DELETION_OF_PLMN_ASSIGNED_IDS",
        "dicEntryId": 1,
        "manAssOpRequestlist": { "typeAllocationCode": ["35693803"] },
    }));
    reassign(&mut server).await;

    assert!(crate::racs::is_retired(&ID), "the UE-held ID is retired");
    assert_eq!(assigns.lock().expect("assigns").len(), 1);
    let cucs = configuration_update_commands(take_sent_ngap(&mut server));
    assert_eq!(cucs.len(), 1);
    assert!(carries_the_new_id(&cucs[0]), "{:02x?}", cucs[0]);
    server.forget_ue(ue);
}

/// A deletion under another TAC leaves the UE alone: no Assign, no command.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_deletion_by_another_tac_leaves_the_ue_alone() {
    let _racs = crate::racs::tests::guard();
    let (_ucmf, port, assigns) = assigning_ucmf().await;
    let _env = UcmfEnvGuard::acquire(port).await;
    let mut server = capturing_ngap_server().await;
    let (ue, ran) = (7_748_003u64, 53);
    racs_ue_holding_id(&mut server, ue, ran, false);

    crate::racs::apply_notification(&serde_json::json!({
        "eventType": "DELETION_OF_PLMN_ASSIGNED_IDS",
        "dicEntryId": 1,
        "manAssOpRequestlist": { "typeAllocationCode": ["86000000"] },
    }));
    reassign(&mut server).await;

    assert!(assigns.lock().expect("assigns").is_empty());
    assert!(take_sent_ngap(&mut server).is_empty());
    let s = server.ue_auth_state.get(ue).expect("UE held");
    assert_eq!(s.amf_ue.ue_radio_capability_id.as_deref(), Some(&ID[..]));
    server.forget_ue(ue);
}

/// A CM-IDLE UE is re-assigned too, but nothing is sent: the new ID waits for
/// its next Registration Accept (TS 23.501 §5.4.4.1a "or when these UEs perform
/// a Registration").
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_idle_ue_gets_the_new_id_at_its_next_registration() {
    let _racs = crate::racs::tests::guard();
    let (_ucmf, port, _assigns) = assigning_ucmf().await;
    let _env = UcmfEnvGuard::acquire(port).await;
    let mut server = capturing_ngap_server().await;
    let (ue, ran) = (7_748_004u64, 54);
    racs_ue_holding_id(&mut server, ue, ran, true);

    crate::racs::apply_notification(&serde_json::json!({
        "eventType": "NEW_VERSION_ID_OF_PLMN_ASSIGNED_IDs",
        "versionId": 6,
    }));
    reassign(&mut server).await;

    assert!(
        take_sent_ngap(&mut server).is_empty(),
        "an idle UE is not paged for it"
    );
    let mut amf_ue = server.ue_auth_state.get(ue).expect("UE held").amf_ue;
    assert_eq!(amf_ue.ue_radio_capability_id.as_deref(), Some(&NEW_ID[..]));
    let mut ie = vec![0x67, NEW_ID.len() as u8];
    ie.extend_from_slice(&NEW_ID);
    assert_eq!(
        crate::racs::nas_ies_for(&mut amf_ue, crate::racs::NasMessage::RegistrationAccept),
        ie,
        "the next Registration Accept carries the new ID"
    );
    server.forget_ue(ue);
}

/// #1046 review: UEs of one model (same TAC and capability) share one UCMF
/// Assign, and a second notice while it is in flight adds none. Both UEs get
/// the one answer, each in its own CONFIGURATION UPDATE COMMAND.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ues_of_one_model_share_one_assign_and_a_second_notice_adds_none() {
    let _racs = crate::racs::tests::guard();
    let (_ucmf, port, assigns) = assigning_ucmf().await;
    let _env = UcmfEnvGuard::acquire(port).await;
    let mut server = capturing_ngap_server().await;
    let (a, b) = (7_748_011u64, 7_748_012u64);
    racs_ue_holding_id(&mut server, a, 61, false);
    racs_ue_holding_id(&mut server, b, 62, false);
    let new_version = serde_json::json!({
        "eventType": "NEW_VERSION_ID_OF_PLMN_ASSIGNED_IDs",
        "versionId": 6,
    });

    crate::racs::apply_notification(&new_version);
    server.process_racs_reassignments();
    // The UCMF says it again before the Assign has come back.
    crate::racs::apply_notification(&new_version);
    server.process_racs_reassignments();
    server.sbi_offload.settle().await;
    server.process_sbi_outcomes().await;

    assert_eq!(
        assigns.lock().expect("assigns").len(),
        1,
        "one Assign for the pair, whatever the number of UEs and notices"
    );
    let cucs = configuration_update_commands(take_sent_ngap(&mut server));
    assert_eq!(cucs.len(), 2, "each UE gets the one answer");
    assert!(cucs.iter().all(|c| carries_the_new_id(c)));
    for ue in [a, b] {
        let s = server.ue_auth_state.get(ue).expect("UE held");
        assert_eq!(
            s.amf_ue.ue_radio_capability_id.as_deref(),
            Some(&NEW_ID[..])
        );
        server.forget_ue(ue);
    }
    assert!(server.racs_assigns.is_empty());
}

/// #1046 review m1/m2: an Assign that fails, or answers an ID a later notice has
/// already retired, is retried with a doubling backoff, not on every NGAP
/// tick, and gives up after [`RACS_ASSIGN_ATTEMPTS`] attempts.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unusable_assign_is_retried_with_backoff_then_given_up() {
    let _racs = crate::racs::tests::guard();
    // First a 500, then an ID under the retired Version ID 05, then 500 again.
    let (_ucmf, port, assigns) = ucmf_answering(|n| (n == 1).then(|| ID.to_vec())).await;
    let _env = UcmfEnvGuard::acquire(port).await;
    let mut server = capturing_ngap_server().await;
    let (ue, ran) = (7_748_021u64, 66);
    racs_ue_holding_id(&mut server, ue, ran, false);
    crate::racs::apply_notification(&serde_json::json!({
        "eventType": "NEW_VERSION_ID_OF_PLMN_ASSIGNED_IDs",
        "versionId": 6,
    }));
    let key = ("35693803".to_string(), vec![0xC0, 0xFF, 0xEE]);

    for attempt in 1..=RACS_ASSIGN_ATTEMPTS as usize {
        reassign(&mut server).await;
        assert_eq!(assigns.lock().expect("assigns").len(), attempt);
        if attempt < RACS_ASSIGN_ATTEMPTS as usize {
            let a = &server.racs_assigns[&key];
            assert_eq!(a.failures as usize, attempt);
            assert!(a.retry_at.is_some(), "a backoff, not an immediate retry");
            // Not due yet: another tick sends nothing.
            reassign(&mut server).await;
            assert_eq!(assigns.lock().expect("assigns").len(), attempt);
            server.racs_assigns.get_mut(&key).expect("waiting").retry_at =
                Some(std::time::Instant::now());
        }
    }
    assert!(
        !server.racs_assigns.contains_key(&key),
        "given up after {RACS_ASSIGN_ATTEMPTS} attempts"
    );
    reassign(&mut server).await;
    assert_eq!(
        assigns.lock().expect("assigns").len(),
        RACS_ASSIGN_ATTEMPTS as usize
    );
    assert!(
        take_sent_ngap(&mut server).is_empty(),
        "no unusable ID reaches the UE"
    );
    server.forget_ue(ue);
}

/// #1046 review m3: the answer is for one capability. A UE whose capability
/// changed while the Assign ran (a UE Radio Capability Info Indication) does
/// not get an ID that maps to its old one.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_answer_for_a_capability_the_ue_no_longer_has_is_not_applied() {
    let _racs = crate::racs::tests::guard();
    let (_ucmf, port, _assigns) = assigning_ucmf().await;
    let _env = UcmfEnvGuard::acquire(port).await;
    let mut server = capturing_ngap_server().await;
    let (ue, ran) = (7_748_031u64, 67);
    racs_ue_holding_id(&mut server, ue, ran, false);
    crate::racs::apply_notification(&serde_json::json!({
        "eventType": "NEW_VERSION_ID_OF_PLMN_ASSIGNED_IDs",
        "versionId": 6,
    }));
    server.process_racs_reassignments();
    // The capability changes before the answer is applied.
    server
        .ue_auth_state
        .with_mut(ue, |s| s.amf_ue.ue_radio_capability = vec![0xBE, 0xEF]);
    server.sbi_offload.settle().await;
    server.process_sbi_outcomes().await;

    let s = server.ue_auth_state.get(ue).expect("UE held");
    assert_ne!(
        s.amf_ue.ue_radio_capability_id.as_deref(),
        Some(&NEW_ID[..]),
        "the ID for the old capability is not installed"
    );
    assert!(take_sent_ngap(&mut server).is_empty());
    server.forget_ue(ue);
}
