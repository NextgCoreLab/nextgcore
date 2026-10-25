//! #981: an off-task SBI answer ends the NGAP poll's SCTP wait, so it is applied
//! when it arrives rather than up to `SCTP_RECV_TIMEOUT` later.
//!
//! Before #981, `poll()` drained the offload's outcomes only once per call, and
//! each call waited out the SCTP receive timeout (100 ms) when no N2 traffic came
//! in. Every SMF round trip an NGAP step waited for (each intra-5GS N2 handover
//! step, an establishment retry, a Service Request re-activation) added up to that.
//!
//! The tests drive `poll()`'s receive step and its SBI-outcome step, not the whole
//! `poll()`: the rest of it drains process-global queues (5GS→EPS answers, network
//! deregistrations, ...) that sibling tests fill and wait on.

use super::*;

/// One `poll()` turn as far as off-task SBI work goes: apply what is in, then wait
/// for N2 or an SBI report. Returns how the receive step ended.
async fn sbi_turn(server: &mut NgapServer) -> nextgcore_sctp::RecvOutcome {
    server.process_sbi_outcomes().await;
    server.receive_n2_or_sbi_report().await.expect("receive")
}

/// A keyed exchange that finishes while `poll()` waits on a quiet socket ends the
/// wait (`Woken`) instead of the full receive timeout.
///
/// REVERT-VERIFIED: without the wake, the receive ends in `Timeout` after 100 ms.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_finished_exchange_ends_the_polls_receive_wait() {
    let mut server = test_ngap_server().await;
    server
        .sbi_offload
        .spawn_keyed((7_981_001, 5), move || async move {
            tokio::time::sleep(Duration::from_millis(10)).await;
            None
        });
    let woke = server.receive_n2_or_sbi_report().await.expect("receive");
    assert_eq!(
        woke,
        nextgcore_sctp::RecvOutcome::Woken,
        "the finished exchange must end the receive wait, not the {SCTP_RECV_TIMEOUT:?} timeout"
    );
    assert!(
        !server.sbi_offload.key_busy((7_981_001, 5)),
        "and its key is freed by that wake, so queued work for it starts at once"
    );
}

/// The real-binary case #981 was found on: TS 23.502 §4.9.1.3.2 steps 3-4. A
/// HANDOVER REQUIRED whose SMFs answer the PREPARING at once is turned into the
/// HANDOVER REQUEST by `poll()`'s turns alone, with no turn waiting out its receive
/// timeout on the way.
///
/// REVERT-VERIFIED: without the wake, the first turn after the HANDOVER REQUIRED
/// waits the full 100 ms (`Timeout`) before the answer is applied.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_handover_request_follows_the_smf_answers_without_a_poll_timeout() {
    let (_smf, smf_port, _seen) = handover_smf().await;
    let mut server = capturing_ngap_server().await;
    let (source, target) = (98_101u64, 98_102u64);
    let gnb_t = 0x9_8102u32;
    seed_gnb_session_with_id(&server, source, 0x9_8101).await;
    seed_gnb_session_with_id(&server, target, gnb_t).await;
    let (ue, ran) = (7_981_101u64, 81u32);
    let mut state = UeNasContext::new(ue, ran, source, false);
    state.registered = true;
    state.amf_ue.allowed_nssai = vec![SNssai { sst: 1, sd: None }];
    server.ue_auth_state.insert(ue, state);
    for (psi, r) in [(1u8, "w981-1"), (2, "w981-2")] {
        server.sm_context_refs.insert((ue, psi), r.to_string());
        server
            .sm_context_smfs
            .insert((ue, psi), ("127.0.0.1".to_string(), smf_port));
    }
    server
        .handle_handover_required(source, &handover_required_pdu(ue, ran, gnb_t, &[1, 2]))
        .await
        .expect("handled");
    let mut sent = Vec::new();
    for _ in 0..50 {
        let woke = sbi_turn(&mut server).await;
        sent.extend(take_sent_ngap(&mut server));
        if !sent.is_empty() {
            break;
        }
        assert_ne!(
            woke,
            nextgcore_sctp::RecvOutcome::Timeout,
            "a poll waited out its {SCTP_RECV_TIMEOUT:?} receive timeout while the SMF \
             answers were in"
        );
    }
    assert_eq!(sent.len(), 1, "{sent:?}");
    assert_eq!(sent[0].0, target, "the HANDOVER REQUEST");
    assert_eq!(
        decoded_handover_request_transfers(&sent[0].1),
        Some(vec![
            (1, ho_request_transfer_for("w981-1")),
            (2, ho_request_transfer_for("w981-2"))
        ])
    );
    server.forget_ue(ue);
}

/// #1129 review M1: a wake by an SBI report is not "poll again at once". `run_async`
/// polls in an inner loop until `poll()` returns `false`, and drains the AMF event
/// channel only between those loops; the NGAP handlers `send(..).await` into that
/// bounded channel. With reports arriving more often than every receive timeout, a
/// `true` here kept the inner loop going until the channel filled and the NGAP task
/// parked on a send only it could unblock. Only N2 data keeps the loop going, as
/// before #981.
#[test]
fn only_n2_data_makes_the_caller_poll_again_at_once() {
    use nextgcore_sctp::RecvOutcome;
    assert!(poll_again_at_once(RecvOutcome::Data));
    assert!(!poll_again_at_once(RecvOutcome::Woken));
    assert!(!poll_again_at_once(RecvOutcome::Timeout));
}
