//! #922 part 2: the N11 calls an NGAP handler makes run off the NGAP task.
//!
//! Each test points one UE's session at a blackholed SMF (192.0.2.1, TEST-NET-1:
//! a connection attempt gets no answer at all, so the SBI client waits out its
//! connect timeout). It then checks two things:
//! - the handler returns at once, and another UE is served meanwhile;
//! - what the procedure sends after the SMF's answer still waits for that answer
//!   (the 3GPP order).
//!
//! Before #922 part 2 each of these calls was awaited on the NGAP task, so every
//! gNB's N2 stalled for the connect timeout.

use super::handler_tests::*;
use super::*;

/// TEST-NET-1 (RFC 5737): nothing answers there.
const BLACKHOLE: (&str, u16) = ("192.0.2.1", 7777);

/// What a handler may take at most when it does not wait for the SMF.
const AT_ONCE: Duration = Duration::from_millis(500);

/// Give `ue` an SM context for `psi` held at the blackholed SMF.
fn hold_blackholed(server: &mut NgapServer, ue: u64, psi: u8, sm_ref: &str) {
    record_amf_session(ue, psi, sm_ref, SLICE.0, SLICE.1);
    server.sm_context_refs.insert((ue, psi), sm_ref.to_string());
    server
        .sm_context_smfs
        .insert((ue, psi), (BLACKHOLE.0.to_string(), BLACKHOLE.1));
}

/// Apply off-task outcomes, collecting what is sent, until `done` holds for the
/// collected PDUs (up to 3 s). Returns them.
async fn apply_until(
    server: &mut NgapServer,
    mut done: impl FnMut(&[(u64, Sent)]) -> bool,
) -> Vec<(u64, Sent)> {
    let mut sent = Vec::new();
    for _ in 0..300 {
        server.process_sbi_outcomes().await;
        sent.extend(
            take_sent_ngap(server)
                .into_iter()
                .map(|(a, p)| (a, decode_sent(&p))),
        );
        if done(&sent) {
            return sent;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("not done after 3 s; sent: {sent:?}");
}

/// Wait until the stand-in SMF has seen a request whose URI ends with `suffix`.
async fn until_called(calls: &Arc<std::sync::Mutex<Vec<SmfCall>>>, suffix: &str) -> SmfCall {
    for _ in 0..300 {
        if let Some(c) = calls
            .lock()
            .expect("calls")
            .iter()
            .find(|(u, _)| u.ends_with(suffix))
        {
            return c.clone();
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("the SMF never saw {suffix}");
}

fn concerns(sent: &[(u64, Sent)], ue: u64) -> Vec<&Sent> {
    sent.iter()
        .map(|(_, s)| s)
        .filter(|s| match s {
            Sent::SetupRequest { amf_ue_ngap_id, .. }
            | Sent::ModifyRequest { amf_ue_ngap_id, .. }
            | Sent::ReleaseCommand { amf_ue_ngap_id, .. }
            | Sent::DownlinkNas { amf_ue_ngap_id, .. } => *amf_ue_ngap_id == ue,
            _ => false,
        })
        .collect()
}

/// Make every SMF join due now.
fn joins_due(server: &mut NgapServer) {
    for j in server.smf_joins.values_mut() {
        j.deadline = Instant::now();
    }
}

/// TS 23.502 §4.3.3.2: a UE-requested PDU Session Modification (0xC9) whose SMF is
/// blackholed does not hold the NGAP task. Another UE's modification is answered
/// meanwhile. The first UE's Modification Command waits for its SMF's answer
/// (step 3b, then step 4).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_modification_to_a_blackholed_smf_does_not_hold_the_ngap_task() {
    let (_smf, port, calls) = activating_smf().await;
    let mut server = capturing_ngap_server().await;
    let (dead, live) = ((7_922_101u64, 121u32), (7_922_102u64, 122u32));
    secured_registered_ue(&mut server, dead.0, dead.1);
    secured_registered_ue(&mut server, live.0, live.1);
    hold_blackholed(&mut server, dead.0, 5, "mod-922-dead");
    hold_session(&mut server, live.0, 5, "mod-922-live", port);
    let request = [0x2E, 0x05, 0x07, 0xC9];

    let started = Instant::now();
    for (ue, ran) in [dead, live] {
        server
            .handle_5gsm_message(ASSOC, ue, ran, &request, None)
            .await
            .expect("handled");
    }
    assert!(
        started.elapsed() < AT_ONCE,
        "the handler waited {:?} for the SMF",
        started.elapsed()
    );
    let sent = apply_until(&mut server, |s| !concerns(s, live.0).is_empty()).await;
    until_called(&calls, "/sm-contexts/mod-922-live/modify").await;
    assert!(
        matches!(concerns(&sent, live.0)[..], [Sent::DownlinkNas { .. }]),
        "the answered UE gets its Modification Command: {sent:?}"
    );
    assert!(
        concerns(&sent, dead.0).is_empty(),
        "nothing goes to the UE before its SMF answers: {sent:?}"
    );
    assert!(server.sbi_offload.key_busy((dead.0, 5)));
    server.forget_ue(dead.0);
    server.forget_ue(live.0);
}

/// TS 23.502 §4.2.3.2, CM-CONNECTED: a Service Request re-activating a session at a
/// blackholed SMF does not hold the NGAP task, and another UE's Service Request is
/// served meanwhile. The Service Accept waits for the ACTIVATING's answer, since it
/// rides the step-12 setup request. At the deadline the UE gets it on its own.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_connected_service_request_to_a_blackholed_smf_does_not_hold_the_ngap_task() {
    let (_smf, port, calls) = activating_smf().await;
    let mut server = capturing_ngap_server().await;
    let (dead, live) = ((7_922_201u64, 123u32), (7_922_202u64, 124u32));
    secured_registered_ue(&mut server, dead.0, dead.1);
    secured_registered_ue(&mut server, live.0, live.1);
    hold_blackholed(&mut server, dead.0, 1, "sr-922-dead");
    hold_session(&mut server, live.0, 1, "sr-922-live", port);

    let started = Instant::now();
    async fn handle(server: &mut NgapServer, (ue, ran): (u64, u32)) -> Vec<(u64, Vec<u8>)> {
        let sr = ue_protect(&service_request(Some(1 << 1)), 0);
        server
            .handle_uplink_nas_transport(ASSOC, &uplink_nas_transport(ue, ran, &sr))
            .await
            .expect("handled");
        take_sent_ngap(server)
    }
    let first = handle(&mut server, dead).await;
    let second = handle(&mut server, live).await;
    assert!(
        started.elapsed() < AT_ONCE,
        "the handlers waited {:?} for the SMF",
        started.elapsed()
    );
    assert!(
        first.is_empty() && second.is_empty(),
        "no Service Accept before the ACTIVATING is answered: {first:?} {second:?}"
    );

    let sent = apply_until(&mut server, |s| !concerns(s, live.0).is_empty()).await;
    let Sent::SetupRequest { items, nas_pdu, .. } = concerns(&sent, live.0)[0] else {
        panic!("the answered UE's setup request: {sent:?}");
    };
    assert_eq!(items, &vec![setup_item(1, transfer_for("sr-922-live"))]);
    assert_protected_service_accept(nas_pdu.as_deref().expect("the Accept rides the setup"));
    assert_eq!(
        until_called(&calls, "/sm-contexts/sr-922-live/modify")
            .await
            .1["upCnxState"],
        "ACTIVATING"
    );
    assert!(concerns(&sent, dead.0).is_empty(), "{sent:?}");

    joins_due(&mut server);
    server.process_smf_join_deadlines().await;
    let sent: Vec<(u64, Sent)> = take_sent_ngap(&mut server)
        .into_iter()
        .map(|(a, p)| (a, decode_sent(&p)))
        .collect();
    let Sent::DownlinkNas { nas_pdu, .. } = concerns(&sent, dead.0)[0] else {
        panic!("a standalone Service Accept at the deadline: {sent:?}");
    };
    assert_protected_service_accept(nas_pdu);
    server.forget_ue(dead.0);
    server.forget_ue(live.0);
}

/// TS 23.502 §4.2.3.2, CM-IDLE: a Service Request whose session to re-activate is
/// at a blackholed SMF does not hold the NGAP task. Its Initial Context Setup (step
/// 12) waits for the ACTIVATING's answer (step 4). At the deadline it goes without
/// that session, and the Service Accept reports the re-activation failed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_idle_service_request_to_a_blackholed_smf_does_not_hold_the_ngap_task() {
    // #1107: `served_guami` is process-global. Unguarded, this fixture's restore put
    // back the list it saw at install, under a test (the EPS→5GS ones) that had set its
    // own meanwhile, and that test's HandoverRequest then had no GUAMI to encode.
    let _guard = crate::test_support::CONTEXT_GUARD.lock().await;
    crate::context::amf_context_init(64, 1024, 4096);
    let _guami = ServeOneGuami::install();
    let mut server = capturing_ngap_server().await;
    seed_gnb_session(&server, 1).await;
    let (old, new) = (7_922_301u64, 7_922_391u64);
    let mut ue = idle_registered_ue(old);
    // The ICS carries the Allowed NSSAI (TS 38.413 §9.2.2.1: one to eight).
    ue.amf_ue.allowed_nssai = vec![crate::context::SNssai {
        sst: SLICE.0,
        sd: SLICE.1,
    }];
    server.ue_auth_state.insert(old, ue);
    hold_blackholed(&mut server, old, 5, "isr-922-dead");
    server.forced_amf_ue_ngap_id = Some(new);
    let tmsi = old as u32;
    // Data (1), uplink data status PSI 5, PDU session status PSI 5.
    let mut inner = vec![0x7E, 0x00, 0x4C, 0x10, 0x00, 0x07, 0xF4, 0x55, 0x6A];
    inner.extend_from_slice(&tmsi.to_be_bytes());
    inner.extend_from_slice(&[0x40, 0x02, 0x20, 0x00, 0x50, 0x02, 0x20, 0x00]);
    let mut nas = protected_service_request([0; 4], tmsi);
    nas.extend_from_slice(&[0x71, 0x00, inner.len() as u8]);
    nas.extend_from_slice(&inner);

    let started = Instant::now();
    server
        .handle_initial_ue_message(1, &service_request_initial_ue(nas))
        .await
        .expect("handled");
    assert!(
        started.elapsed() < AT_ONCE,
        "the handler waited {:?} for the SMF",
        started.elapsed()
    );
    assert!(
        take_sent_ngap(&mut server).is_empty(),
        "no Initial Context Setup before the ACTIVATING is answered"
    );
    assert!(
        server.sbi_offload.key_busy((new, 5)),
        "the ACTIVATING is in flight"
    );
    assert_eq!(server.smf_joins.len(), 1);

    joins_due(&mut server);
    server.process_smf_join_deadlines().await;
    let sent = take_sent_ngap(&mut server);
    let ics: Vec<_> = sent
        .iter()
        .filter(|(_, p)| decode_sent(p) == Sent::Other(Some(14)))
        .collect();
    assert_eq!(
        ics.len(),
        1,
        "one Initial Context Setup at the deadline: {sent:?}"
    );
    assert!(
        !server.up_active.contains(&(new, 5)),
        "the unanswered session is not in it"
    );
    server.forced_amf_ue_ngap_id = None;
    server.forget_ue(new);
}

/// #778, TS 23.502 §4.2.3.3 step 4: a queued downlink setup whose ACTIVATING goes to
/// a blackholed SMF does not hold the NGAP task, and another UE's is delivered
/// meanwhile. The setup request waits for the SMF's transfer.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_downlink_setup_activated_at_a_blackholed_smf_does_not_hold_the_ngap_task() {
    let _q = crate::test_support::CONNECTED_DOWNLINK_LOCK.lock().await;
    let (_smf, port, calls) = activating_smf().await;
    let mut server = capturing_ngap_server().await;
    let (dead, live) = ((7_922_401u64, 125u32), (7_922_402u64, 126u32));
    let (dead_supi, live_supi) = ("imsi-001010009224010", "imsi-001010009224020");
    secured_registered_ue(&mut server, dead.0, dead.1);
    secured_registered_ue(&mut server, live.0, live.1);
    with_supi(&mut server, dead.0, dead_supi);
    with_supi(&mut server, live.0, live_supi);
    hold_blackholed(&mut server, dead.0, 2, "dl-922-dead");
    hold_session(&mut server, live.0, 2, "dl-922-live", port);
    for supi in [dead_supi, live_supi] {
        let resp = n1n2_transfer(supi, 2, Some(("PDU_RES_SETUP_REQ", None)), None).await;
        assert_eq!(resp.status, 200);
    }

    let started = Instant::now();
    server.process_connected_downlinks().await;
    assert!(
        started.elapsed() < AT_ONCE,
        "the delivery waited {:?} for the SMF",
        started.elapsed()
    );
    let sent = apply_until(&mut server, |s| !concerns(s, live.0).is_empty()).await;
    assert_eq!(
        concerns(&sent, live.0),
        vec![&Sent::SetupRequest {
            amf_ue_ngap_id: live.0,
            ran_ue_ngap_id: live.1,
            nas_pdu: None,
            items: vec![setup_item(2, transfer_for("dl-922-live"))],
        }]
    );
    until_called(&calls, "/sm-contexts/dl-922-live/modify").await;
    assert!(concerns(&sent, dead.0).is_empty(), "{sent:?}");
    assert!(server.sbi_offload.key_busy((dead.0, 2)));
    server.forget_ue(dead.0);
    server.forget_ue(live.0);
}

/// TS 23.502 §4.2.6 step 5: the DEACTIVATED after an AN release goes to a blackholed
/// SMF without holding the NGAP task. The other session's DEACTIVATED still reaches
/// its SMF.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_an_release_deactivation_at_a_blackholed_smf_does_not_hold_the_ngap_task() {
    let (_smf, port, calls) = activating_smf().await;
    let mut server = capturing_ngap_server().await;
    let (ue, ran) = (7_922_501u64, 127u32);
    secured_registered_ue(&mut server, ue, ran);
    hold_blackholed(&mut server, ue, 1, "an-922-dead");
    hold_session(&mut server, ue, 2, "an-922-live", port);

    let started = Instant::now();
    server
        .handle_ue_context_release_complete(ASSOC, &release_complete_pdu(ue, Some(ran)))
        .await
        .expect("handled");
    assert!(
        started.elapsed() < AT_ONCE,
        "the handler waited {:?} for the SMF",
        started.elapsed()
    );
    let (_, body) = until_called(&calls, "/sm-contexts/an-922-live/modify").await;
    assert_eq!(body["upCnxState"], "DEACTIVATED");
    assert!(
        server.sbi_offload.key_busy((ue, 1)),
        "the other is still on its way"
    );
    server.forget_ue(ue);
}

/// TS 23.502 §4.2.6: an AN release of a UE that is not registered releases its
/// sessions at the SMF, and a blackholed one does not hold the UE CONTEXT RELEASE
/// COMMAND.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_release_of_an_unregistered_ue_does_not_wait_for_a_blackholed_smf() {
    let (_smf, port, calls) = activating_smf().await;
    let mut server = capturing_ngap_server().await;
    let (ue, ran) = (7_922_601u64, 128u32);
    secured_registered_ue(&mut server, ue, ran);
    server.ue_auth_state.with_mut(ue, |s| s.registered = false);
    hold_blackholed(&mut server, ue, 1, "rel-922-dead");
    hold_session(&mut server, ue, 2, "rel-922-live", port);
    let request = nextgcore_ngap::builder::build_ue_context_release_request(
        &nextgcore_ngap::types::UeContextReleaseRequest {
            amf_ue_ngap_id: ue,
            ran_ue_ngap_id: ran,
            cause: nextgcore_ngap::types::Cause::RadioNetwork(
                nextgcore_ngap::types::CauseRadioNetwork::UserInactivity,
            ),
        },
    )
    .expect("encode");

    let started = Instant::now();
    server
        .handle_ue_context_release(ASSOC, &request)
        .await
        .expect("handled");
    assert!(
        started.elapsed() < AT_ONCE,
        "the handler waited {:?} for the SMF",
        started.elapsed()
    );
    let sent = take_sent_ngap(&mut server);
    assert!(
        sent.iter()
            .any(|(_, p)| decode_sent(p) == Sent::Other(Some(41))),
        "the UE Context Release Command went at once: {sent:?}"
    );
    until_called(&calls, "/sm-contexts/rel-922-live/release").await;
    server.forget_ue(ue);
}

/// A de-registration's ReleaseSMContexts (`release_all_pdu_sessions`) go off the
/// NGAP task, so a blackholed SMF does not hold it. The other session is released at
/// its SMF.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_deregistration_does_not_wait_for_a_blackholed_smf() {
    let (_smf, port, calls) = activating_smf().await;
    let mut server = capturing_ngap_server().await;
    let (ue, ran) = (7_922_701u64, 129u32);
    secured_registered_ue(&mut server, ue, ran);
    hold_blackholed(&mut server, ue, 1, "dereg-922-dead");
    hold_session(&mut server, ue, 2, "dereg-922-live", port);

    let dereg = ue_protect(&switch_off_deregistration_request(), 0);
    let started = Instant::now();
    server
        .handle_uplink_nas_transport(ASSOC, &uplink_nas_transport(ue, ran, &dereg))
        .await
        .expect("handled");
    assert!(
        started.elapsed() < AT_ONCE,
        "the handler waited {:?} for the SMF",
        started.elapsed()
    );
    until_called(&calls, "/sm-contexts/dereg-922-live/release").await;
    assert!(
        server.sbi_offload.key_busy((ue, 1)),
        "the blackholed release still runs: it is durable"
    );
}

// ---- #1086 review: the join deadline and the connection-ended guard ----

/// The upCnxStates the slow stand-in SMF saw for `sm_ref`, waiting (up to 5 s)
/// until there are `n` of them. Off-task outcomes are applied meanwhile, as `poll`
/// does: that is what starts the next job queued for a key.
async fn up_cnx_states_of(
    server: &mut NgapServer,
    seen: &Arc<std::sync::Mutex<Vec<(String, String, Instant)>>>,
    sm_ref: &str,
    n: usize,
) -> Vec<String> {
    let states = || -> Vec<String> {
        seen.lock()
            .expect("seen")
            .iter()
            .filter(|(r, _, _)| r == sm_ref)
            .map(|(_, s, _)| s.clone())
            .collect()
    };
    for _ in 0..500 {
        if states().len() >= n {
            break;
        }
        server.process_sbi_outcomes().await;
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    states()
}

/// Apply outcomes until the only join left waits for just `psi` (up to 3 s).
async fn until_join_waits_only_for(server: &mut NgapServer, psi: u8) {
    for _ in 0..300 {
        server.process_sbi_outcomes().await;
        if server
            .smf_joins
            .values()
            .all(|j| j.waiting.len() == 1 && j.waiting.contains(&psi))
            && !server.smf_joins.is_empty()
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("the join never narrowed to PSI {psi}");
}

/// A CM-IDLE UE holding PSI 5 at `fast` and PSI 6 at `slow`, and the protected
/// Service Request (Initial UE Message) that re-activates both.
fn idle_ue_with_two_sessions(
    server: &mut NgapServer,
    old: u64,
    new: u64,
    fast: u16,
    slow: u16,
    refs: (&str, &str),
) -> Vec<u8> {
    let mut ue = idle_registered_ue(old);
    ue.amf_ue.allowed_nssai = vec![crate::context::SNssai {
        sst: SLICE.0,
        sd: SLICE.1,
    }];
    server.ue_auth_state.insert(old, ue);
    hold_session(server, old, 5, refs.0, fast);
    hold_session(server, old, 6, refs.1, slow);
    server.forced_amf_ue_ngap_id = Some(new);
    let tmsi = old as u32;
    // Data (1); uplink data status and PDU session status: PSI 5 and 6.
    let mut inner = vec![0x7E, 0x00, 0x4C, 0x10, 0x00, 0x07, 0xF4, 0x55, 0x6A];
    inner.extend_from_slice(&tmsi.to_be_bytes());
    inner.extend_from_slice(&[0x40, 0x02, 0x60, 0x00, 0x50, 0x02, 0x60, 0x00]);
    let mut nas = protected_service_request([0; 4], tmsi);
    nas.extend_from_slice(&[0x71, 0x00, inner.len() as u8]);
    nas.extend_from_slice(&inner);
    service_request_initial_ue(nas)
}

/// TS 23.502 §4.2.3.2, CM-IDLE, at the join deadline: PSI 5's SMF answered and
/// PSI 6's had not. The ICS carries PSI 5 only, and PSI 6's ACTIVATING, which then
/// succeeds late, is rolled back (DEACTIVATED, after it on its key). Otherwise the
/// SMF would wait in ACTIVATING for a setup that never comes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_idle_service_requests_unanswered_activation_is_rolled_back_at_the_deadline() {
    // #1107: `served_guami` is process-global. Unguarded, this fixture's restore put
    // back the list it saw at install, under a test (the EPS→5GS ones) that had set its
    // own meanwhile, and that test's HandoverRequest then had no GUAMI to encode.
    let _guard = crate::test_support::CONTEXT_GUARD.lock().await;
    crate::context::amf_context_init(64, 1024, 4096);
    let _guami = ServeOneGuami::install();
    let (_fast, fast_port, _calls) = activating_smf().await;
    let (_slow, slow_port, seen) = slow_up_cnx_smf(Duration::from_millis(800)).await;
    let mut server = capturing_ngap_server().await;
    seed_gnb_session(&server, 1).await;
    let (old, new) = (7_922_311u64, 7_922_312u64);
    let pdu = idle_ue_with_two_sessions(
        &mut server,
        old,
        new,
        fast_port,
        slow_port,
        ("isr-dl-fast", "isr-dl-slow"),
    );
    server
        .handle_initial_ue_message(1, &pdu)
        .await
        .expect("handled");
    until_join_waits_only_for(&mut server, 6).await;

    joins_due(&mut server);
    server.process_smf_join_deadlines().await;
    let ics: Vec<_> = take_sent_ngap(&mut server)
        .into_iter()
        .filter(|(_, p)| decode_sent(p) == Sent::Other(Some(14)))
        .collect();
    assert_eq!(ics.len(), 1, "the ICS goes at the deadline");
    assert!(server.up_active.contains(&(new, 5)), "with PSI 5");
    assert!(!server.up_active.contains(&(new, 6)), "without PSI 6");
    assert_eq!(
        up_cnx_states_of(&mut server, &seen, "isr-dl-slow", 2).await,
        vec!["ACTIVATING", "DEACTIVATED"],
        "the late ACTIVATING is rolled back"
    );
    server.forced_amf_ue_ngap_id = None;
    server.forget_ue(new);
}

/// TS 23.502 §4.2.3.2, CM-CONNECTED, at the join deadline: the setup with the
/// Service Accept carries the answered PSI 5, and PSI 6's late ACTIVATING is
/// rolled back.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_connected_service_requests_unanswered_activation_is_rolled_back_at_the_deadline() {
    let (_fast, fast_port, _calls) = activating_smf().await;
    let (_slow, slow_port, seen) = slow_up_cnx_smf(Duration::from_millis(800)).await;
    let mut server = capturing_ngap_server().await;
    let (ue, ran) = (7_922_211u64, 131u32);
    secured_registered_ue(&mut server, ue, ran);
    hold_session(&mut server, ue, 5, "csr-dl-fast", fast_port);
    hold_session(&mut server, ue, 6, "csr-dl-slow", slow_port);
    let sr = ue_protect(&service_request(Some((1 << 5) | (1 << 6))), 0);
    server
        .handle_uplink_nas_transport(ASSOC, &uplink_nas_transport(ue, ran, &sr))
        .await
        .expect("handled");
    until_join_waits_only_for(&mut server, 6).await;

    joins_due(&mut server);
    server.process_smf_join_deadlines().await;
    let sent: Vec<(u64, Sent)> = take_sent_ngap(&mut server)
        .into_iter()
        .map(|(a, p)| (a, decode_sent(&p)))
        .collect();
    let setups: Vec<&Sent> = concerns(&sent, ue)
        .into_iter()
        .filter(|s| matches!(s, Sent::SetupRequest { .. }))
        .collect();
    let [Sent::SetupRequest { items, nas_pdu, .. }] = setups[..] else {
        panic!("one setup request at the deadline: {sent:?}");
    };
    assert_eq!(items, &vec![setup_item(5, transfer_for("csr-dl-fast"))]);
    assert_protected_service_accept(nas_pdu.as_deref().expect("the Accept rides it"));
    assert_eq!(
        up_cnx_states_of(&mut server, &seen, "csr-dl-slow", 2).await,
        vec!["ACTIVATING", "DEACTIVATED"],
        "the late ACTIVATING is rolled back"
    );
    server.forget_ue(ue);
}

/// TS 23.502 §4.2.6 during a CM-IDLE Service Request's join: the gNB releases the
/// UE's new connection before the SMF answers. When the ACTIVATING's answer
/// arrives, no Initial Context Setup goes to the released connection, and the
/// activation is rolled back. The SMF ends DEACTIVATED.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_an_release_during_the_join_sends_no_initial_context_setup() {
    // #1107: `served_guami` is process-global. Unguarded, this fixture's restore put
    // back the list it saw at install, under a test (the EPS→5GS ones) that had set its
    // own meanwhile, and that test's HandoverRequest then had no GUAMI to encode.
    let _guard = crate::test_support::CONTEXT_GUARD.lock().await;
    crate::context::amf_context_init(64, 1024, 4096);
    let _guami = ServeOneGuami::install();
    let (_fast, fast_port, _calls) = activating_smf().await;
    let (_slow, slow_port, seen) = slow_up_cnx_smf(Duration::from_millis(400)).await;
    let mut server = capturing_ngap_server().await;
    seed_gnb_session(&server, 1).await;
    let (old, new) = (7_922_321u64, 7_922_322u64);
    let pdu = idle_ue_with_two_sessions(
        &mut server,
        old,
        new,
        fast_port,
        slow_port,
        ("isr-an-fast", "isr-an-slow"),
    );
    server
        .handle_initial_ue_message(1, &pdu)
        .await
        .expect("handled");
    // The AN release lands while the join waits.
    server
        .handle_ue_context_release_complete(1, &release_complete_pdu(new, Some(512)))
        .await
        .expect("handled");
    assert!(server.ue_auth_state.get(new).expect("ue").is_cm_idle());
    for _ in 0..300 {
        server.process_sbi_outcomes().await;
        if server.smf_joins.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(server.smf_joins.is_empty(), "both answers came in");
    assert!(
        !take_sent_ngap(&mut server)
            .iter()
            .any(|(_, p)| decode_sent(p) == Sent::Other(Some(14))),
        "no ICS to the released connection"
    );
    assert!(server.up_active.is_empty() || !server.up_active.contains(&(new, 5)));
    let states = up_cnx_states_of(&mut server, &seen, "isr-an-slow", 3).await;
    assert_eq!(
        states.last().map(String::as_str),
        Some("DEACTIVATED"),
        "the SMF ends DEACTIVATED: {states:?}"
    );
    assert!(
        states.len() >= 3,
        "the AN release's DEACTIVATED and the roll-back both follow the ACTIVATING: \
         {states:?}"
    );
    server.forced_amf_ue_ngap_id = None;
    server.forget_ue(new);
}

// ---------------------------------------------------------------------------
// #922 part 3: the N2 SM relays, the Path Switch, the Modify Indication and the
// registration update's sessions
// ---------------------------------------------------------------------------

/// The PDU sessions a PDU SESSION RESOURCE MODIFY CONFIRM reports failed, or `None`
/// when `pdu` is not a Modify Confirm.
fn modify_confirm_failed_psis(pdu: &[u8]) -> Option<Vec<u8>> {
    use g::PDUSessionResourceModifyConfirmProtocolIEs_EntryValue as Ie;
    use nextgcore_ngap_gen::generated as g;
    let Ok(g::NGAP_PDU::SuccessfulOutcome(out)) = nextgcore_ngap_gen::decode(pdu) else {
        return None;
    };
    let g::SuccessfulOutcomeValue::Id_PDUSessionResourceModifyIndication(confirm) = out.value
    else {
        return None;
    };
    let mut failed = Vec::new();
    for e in confirm.protocol_i_es.0 {
        if let Ie::Id_PDUSessionResourceFailedToModifyListModCfm(l) = e.value {
            failed.extend(l.0.into_iter().map(|i| i.pdu_session_id.0));
        }
    }
    Some(failed)
}

/// TS 23.502 §4.9.1.2.2 steps 2-7: a PATH SWITCH REQUEST whose session is held at a
/// blackholed SMF does not hold the NGAP task. Another UE's Path Switch is acknowledged
/// meanwhile. The first is answered only when the AMF stops waiting: nothing was
/// switched, so a PATH SWITCH REQUEST FAILURE (TS 38.413 §8.4.4.3), and the UE stays on
/// its source.
///
/// REVERT-VERIFIED: with the Update SM Context awaited on the NGAP task, the handler
/// takes the connect timeout.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_path_switch_to_a_blackholed_smf_does_not_hold_the_ngap_task() {
    crate::context::amf_context_init(64, 1024, 4096);
    let (_smf, port, _calls) = path_switch_smf().await;
    let mut server = capturing_ngap_server().await;
    let (source, target) = (97_923_001u64, 97_923_002u64);
    seed_gnb_session(&server, source).await;
    seed_gnb_session(&server, target).await;
    let (dead, live) = (7_923_011u64, 7_923_012u64);
    for (ue, ran) in [(dead, 31u32), (live, 32)] {
        let mut state = UeNasContext::new(ue, ran, source, false);
        state.registered = true;
        server.ue_auth_state.insert(ue, state);
    }
    hold_blackholed(&mut server, dead, 5, "ps922-dead-5");
    hold_session(&mut server, live, 5, "ps922-live-5", port);

    let started = Instant::now();
    for (ue, ran) in [(dead, 41u32), (live, 42)] {
        server
            .handle_path_switch_request(target, &path_switch_request_pdu(ue, ran, &[5]))
            .await
            .expect("handled");
    }
    assert!(
        started.elapsed() < AT_ONCE,
        "the handler waited {:?} for the SMF",
        started.elapsed()
    );
    // The answered UE is acknowledged and moved to the target.
    let mut acks = Vec::new();
    for _ in 0..300 {
        server.process_sbi_outcomes().await;
        acks.extend(take_sent_ngap(&mut server));
        if !acks.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(acks.len(), 1, "{acks:?}");
    let (switched, _) = decoded_path_switch_ack(&acks[0].1).expect("an Acknowledge");
    assert_eq!(switched, vec![(5, transfer_for("ps922-live-5"))]);
    assert_eq!(
        server.ue_auth_state.get(live).expect("UE").association_id,
        target
    );
    // The blackholed one: nothing yet, and still on its source.
    assert_eq!(
        server.ue_auth_state.get(dead).expect("UE").association_id,
        source
    );

    joins_due(&mut server);
    server.process_smf_join_deadlines().await;
    let sent = take_sent_ngap(&mut server);
    assert_eq!(sent.len(), 1, "{sent:?}");
    let (amf, ran, released) =
        decoded_path_switch_failure(&sent[0].1).expect("a PATH SWITCH REQUEST FAILURE");
    assert_eq!((amf, ran, released.len()), (dead, 41, 1));
    assert_eq!(
        server.ue_auth_state.get(dead).expect("UE").association_id,
        source
    );
    forget_amf_sessions(dead);
    forget_amf_sessions(live);
    server.forget_ue(dead);
    server.forget_ue(live);
}

/// TS 38.413 §8.2.4: a PDU SESSION RESOURCE MODIFY INDICATION for a session at a
/// blackholed SMF does not hold the NGAP task, and its Modify Confirm waits for the
/// SMF. When the AMF stops waiting, the session is reported failed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_modify_indication_to_a_blackholed_smf_does_not_hold_the_ngap_task() {
    let mut server = capturing_ngap_server().await;
    let (ue, ran) = (7_923_021u64, 51u32);
    secured_registered_ue(&mut server, ue, ran);
    hold_blackholed(&mut server, ue, 5, "mi922-dead-5");
    let indication = crate::ngap_asn1::tests::modify_indication_bytes(ue, ran, &[(5, vec![0x51])]);

    let started = Instant::now();
    server
        .handle_pdu_session_resource_modify_indication(ASSOC, &indication)
        .await
        .expect("handled");
    assert!(started.elapsed() < AT_ONCE, "{:?}", started.elapsed());
    server.process_sbi_outcomes().await;
    assert!(
        take_sent_ngap(&mut server).is_empty(),
        "no Confirm before the SMF answers"
    );

    joins_due(&mut server);
    server.process_smf_join_deadlines().await;
    let sent = take_sent_ngap(&mut server);
    assert_eq!(sent.len(), 1, "{sent:?}");
    assert_eq!(sent[0].0, ASSOC);
    assert_eq!(modify_confirm_failed_psis(&sent[0].1), Some(vec![5]));
    forget_amf_sessions(ue);
    server.forget_ue(ue);
}

/// TS 23.502 §4.2.2.2.2 step 21: a connected UE's registration update re-activating a
/// session at a blackholed SMF does not hold the NGAP task, and the Accept waits for
/// the SMF. When the AMF stops waiting, the Accept goes on its own, reporting the
/// re-activation failed (TS 24.501 §8.2.7.15).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_registration_update_to_a_blackholed_smf_does_not_hold_the_ngap_task() {
    let mut server = capturing_ngap_server().await;
    let (ue, ran) = (7_923_031u64, 61u32);
    registered_ue_with_guti(&mut server, ue, ran);
    hold_blackholed(&mut server, ue, 1, "ru922-dead-1");
    let rr = ue_protect(
        &update_registration_request(
            crate::gmm_build::registration_type::PERIODIC_UPDATING,
            Some(1 << 1),
            None,
        ),
        0,
    );

    let started = Instant::now();
    let _ = server
        .handle_uplink_nas_transport(ASSOC, &uplink_nas_transport(ue, ran, &rr))
        .await;
    assert!(started.elapsed() < AT_ONCE, "{:?}", started.elapsed());
    server.process_sbi_outcomes().await;
    assert!(
        take_sent_ngap(&mut server).is_empty(),
        "no Accept before the SMF answers"
    );

    joins_due(&mut server);
    server.process_smf_join_deadlines().await;
    let sent: Vec<Sent> = take_sent_ngap(&mut server)
        .into_iter()
        .map(|(_, p)| decode_sent(&p))
        .collect();
    let [Sent::DownlinkNas { nas_pdu, .. }] = sent.as_slice() else {
        panic!("a standalone Accept: {sent:?}");
    };
    let accept = registration_accept_of(nas_pdu);
    assert_eq!(accept.pdu_session_reactivation_result, Some(1 << 1));
    forget_amf_sessions(ue);
    server.forget_ue(ue);
}

/// The N2 SM containers nothing waits for -- a Setup Response's failed session, a
/// Notify's notified and released sessions -- are relayed off the NGAP task: against
/// a blackholed SMF the handlers return at once.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn n2_sm_relays_to_a_blackholed_smf_do_not_hold_the_ngap_task() {
    use nextgcore_ngap::{builder as b, types as t};
    let mut server = capturing_ngap_server().await;
    let (ue, ran) = (7_923_041u64, 71u32);
    secured_registered_ue(&mut server, ue, ran);
    for psi in [1u8, 2, 3] {
        hold_blackholed(&mut server, ue, psi, &format!("relay922-{psi}"));
    }
    let setup = b::build_pdu_session_resource_setup_response(&t::PduSessionResourceSetupResponse {
        amf_ue_ngap_id: ue,
        ran_ue_ngap_id: ran,
        setup_list: vec![],
        failed_list: vec![t::PduSessionResourceFailedItem {
            pdu_session_id: 1,
            transfer: vec![0x11],
        }],
    })
    .expect("setup response");
    let notify = b::build_pdu_session_resource_notify(&t::PduSessionResourceNotify {
        amf_ue_ngap_id: ue,
        ran_ue_ngap_id: ran,
        notify_list: vec![t::PduSessionResourceNotifyItem {
            pdu_session_id: 2,
            transfer: vec![0x21],
        }],
        released_list: vec![t::PduSessionResourceReleasedItem {
            pdu_session_id: 3,
            transfer: vec![0x31],
        }],
    })
    .expect("notify");

    let started = Instant::now();
    server
        .handle_pdu_session_resource_setup_response(ASSOC, &setup)
        .await
        .expect("handled");
    server
        .handle_pdu_session_resource_notify(ASSOC, &notify)
        .await
        .expect("handled");
    assert!(started.elapsed() < AT_ONCE, "{:?}", started.elapsed());
    assert!(
        (1..=3).all(|psi| server.sbi_offload.key_busy((ue, psi))),
        "each relay is queued on its session"
    );
    forget_amf_sessions(ue);
    server.forget_ue(ue);
}

/// #1138 review M1/M2: a UE whose NG connection is released (CM-IDLE) while its
/// registration update waits for the SMFs gets no Accept on the released connection
/// at the deadline, and the session its SMF did activate is rolled back (DEACTIVATED).
///
/// REVERT-VERIFIED: without the CM-IDLE check in `finish_registration_update`, the
/// Accept goes out in a setup request on the released connection.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_registration_update_released_during_its_join_sends_no_accept() {
    let (_smf, port, calls) = activating_smf().await;
    let mut server = capturing_ngap_server().await;
    let (ue, ran) = (7_923_051u64, 81u32);
    registered_ue_with_guti(&mut server, ue, ran);
    hold_session(&mut server, ue, 1, "ru922-live-1", port);
    hold_blackholed(&mut server, ue, 2, "ru922-dead-2");
    let rr = ue_protect(
        &update_registration_request(
            crate::gmm_build::registration_type::PERIODIC_UPDATING,
            Some((1 << 1) | (1 << 2)),
            None,
        ),
        0,
    );
    let _ = server
        .handle_uplink_nas_transport(ASSOC, &uplink_nas_transport(ue, ran, &rr))
        .await;
    until_called(&calls, "/sm-contexts/ru922-live-1/modify").await;
    until_join_waits_only_for(&mut server, 2).await;

    // AN release: the UE is CM-IDLE, on the same association and RAN UE NGAP ID.
    server.ue_auth_state.with_mut(ue, |s| s.cm_idle = true);
    joins_due(&mut server);
    server.process_smf_join_deadlines().await;
    assert!(
        take_sent_ngap(&mut server).is_empty(),
        "no Accept on the released connection"
    );
    // PSI 2's calls hang at the blackhole, so wait for PSI 1's roll-back itself.
    let states = || -> Vec<String> {
        calls
            .lock()
            .expect("calls")
            .iter()
            .filter(|(u, _)| u.ends_with("/sm-contexts/ru922-live-1/modify"))
            .map(|(_, b)| b["upCnxState"].as_str().unwrap_or_default().to_string())
            .collect()
    };
    for _ in 0..300 {
        if states().len() >= 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(states(), vec!["ACTIVATING", "DEACTIVATED"], "rolled back");
    forget_amf_sessions(ue);
    server.forget_ue(ue);
}

/// #1138 review M2: a UE that goes CM-IDLE while its PATH SWITCH REQUEST waits for the
/// SMFs is not moved to the target: at the deadline the target gets a PATH SWITCH
/// REQUEST FAILURE, even though one session was switched.
///
/// REVERT-VERIFIED: without the CM-IDLE filter in `finish_path_switch`, an Acknowledge
/// goes out and the UE is relocated.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_path_switch_whose_ue_goes_idle_during_its_join_is_failed() {
    crate::context::amf_context_init(64, 1024, 4096);
    let (_smf, port, calls) = path_switch_smf().await;
    let mut server = capturing_ngap_server().await;
    let (source, target) = (97_923_011u64, 97_923_012u64);
    seed_gnb_session(&server, source).await;
    seed_gnb_session(&server, target).await;
    let ue = 7_923_061u64;
    let mut state = UeNasContext::new(ue, 33, source, false);
    state.registered = true;
    server.ue_auth_state.insert(ue, state);
    hold_session(&mut server, ue, 5, "ps922-idle-5", port);
    hold_blackholed(&mut server, ue, 6, "ps922-idle-6");
    server
        .handle_path_switch_request(target, &path_switch_request_pdu(ue, 43, &[5, 6]))
        .await
        .expect("handled");
    for _ in 0..300 {
        if !calls.lock().expect("calls").is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    until_join_waits_only_for(&mut server, 6).await;

    server.ue_auth_state.with_mut(ue, |s| s.cm_idle = true);
    joins_due(&mut server);
    server.process_smf_join_deadlines().await;
    let sent = take_sent_ngap(&mut server);
    assert_eq!(sent.len(), 1, "{sent:?}");
    assert!(
        decoded_path_switch_failure(&sent[0].1).is_some(),
        "a PATH SWITCH REQUEST FAILURE, not an Acknowledge"
    );
    assert_eq!(
        server.ue_auth_state.get(ue).expect("UE").association_id,
        source
    );
    forget_amf_sessions(ue);
    server.forget_ue(ue);
}

/// #1138 review m1, TS 24.501 §5.5.1.3.8 e): a REGISTRATION REQUEST repeated with the
/// same IEs while the first one's Accept waits for the SMF is not treated further (the
/// first procedure goes on, one join); one with different IEs aborts the first and is
/// progressed (a new join, the old one gone).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_repeated_registration_request_during_the_join_follows_5_5_1_3_8_e() {
    let mut server = capturing_ngap_server().await;
    let (ue, ran) = (7_923_071u64, 91u32);
    registered_ue_with_guti(&mut server, ue, ran);
    hold_blackholed(&mut server, ue, 1, "ru922-rep-1");
    hold_blackholed(&mut server, ue, 2, "ru922-rep-2");
    let request = |uds: u16, pss: Option<u16>, count: u8| {
        ue_protect(
            &update_registration_request(
                crate::gmm_build::registration_type::PERIODIC_UPDATING,
                Some(uds),
                pss,
            ),
            count,
        )
    };
    let joins = |server: &NgapServer| -> Vec<u64> {
        let mut ids: Vec<u64> = server
            .smf_joins
            .iter()
            .filter(|(_, j)| j.amf_ue_ngap_id == ue)
            .map(|(id, _)| *id)
            .collect();
        ids.sort_unstable();
        ids
    };

    let _ = server
        .handle_uplink_nas_transport(
            ASSOC,
            &uplink_nas_transport(ue, ran, &request(1 << 1, None, 0)),
        )
        .await;
    let first = joins(&server);
    assert_eq!(first.len(), 1, "the first request waits for its SMF");

    // The same IEs again: the first procedure goes on.
    let _ = server
        .handle_uplink_nas_transport(
            ASSOC,
            &uplink_nas_transport(ue, ran, &request(1 << 1, None, 1)),
        )
        .await;
    assert_eq!(joins(&server), first, "not treated further");

    // Different IEs: the first is aborted, this one progressed.
    let _ = server
        .handle_uplink_nas_transport(
            ASSOC,
            &uplink_nas_transport(ue, ran, &request((1 << 1) | (1 << 2), None, 2)),
        )
        .await;
    let second = joins(&server);
    assert_eq!(second.len(), 1, "{second:?}");
    assert_ne!(second, first, "the first join is gone, a new one waits");
    assert!(take_sent_ngap(&mut server).is_empty(), "no Accept yet");
    forget_amf_sessions(ue);
    server.forget_ue(ue);
}
