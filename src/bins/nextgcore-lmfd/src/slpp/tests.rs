//! SLPP at the LMF (#557).
//!
//! The byte vectors are the hand-derived goldens of `nextgcore-slpp-gen`
//! (`src/libs/nextgcore-slpp-gen/src/tests.rs`), copied unchanged. nextgsim's
//! UE interop test drives its SLPP endpoint with the same LMF-side bytes, so
//! one set of vectors pins both ends of the exchange.

use super::*;

use super::golden::*;

const UE_A: [u8; 3] = [0xA5, 0xA5, 0xA5];
const UE_B: [u8; 3] = [0x5A, 0x5A, 0x5A];

#[test]
fn the_capability_request_is_the_golden() {
    assert_eq!(
        build_request_capabilities(1, None).expect("builds"),
        REQUEST_CAPABILITIES
    );
}

#[test]
fn the_location_request_is_the_golden() {
    assert_eq!(
        build_request_location_information(2, None).expect("builds"),
        REQUEST_LOCATION_INFORMATION
    );
}

#[test]
fn provide_capabilities_reads_ue_assisted_sl_rtt() {
    assert_eq!(
        decode_uplink(&PROVIDE_CAPABILITIES).expect("decodes"),
        Uplink::Capabilities {
            tid: Some(1),
            app_id: Some(UE_A.to_vec()),
            sl_rtt_ue_assisted: true,
        }
    );
}

/// 246338 at k = 2 is the bin [324, 328) Tc (TS 38.133 table 10.4A.4.1.1-1),
/// whose midpoint is 326 Tc.
#[test]
fn provide_location_information_yields_the_half_at_the_bin_midpoint() {
    let Uplink::Location {
        tid,
        app_id,
        halves,
        sl_rtt_error,
    } = decode_uplink(&PROVIDE_LOCATION_INFORMATION).expect("decodes")
    else {
        panic!("not a location report");
    };
    assert_eq!(tid, Some(2));
    assert_eq!(app_id, Some(UE_A.to_vec()));
    assert_eq!(sl_rtt_error, None);
    assert_eq!(
        halves,
        vec![SlRttHalf {
            peer: UE_B.to_vec(),
            rx_tx_tc: 326.0,
        }]
    );
}

/// TS 38.133 §10.4A.4.1.1, the table rows themselves: for k = 2,
/// value 1 is [-985024, -985020), 246257 is [0, 4), 492512 is
/// [985020, 985024), and 0 and 492513 are open-ended. For k = 3, 246256 is
/// [985016, 985024).
#[test]
fn the_rx_tx_mapping_follows_the_38_133_tables() {
    assert_eq!(rx_tx_tc(2, 1), Some(-985_022.0));
    assert_eq!(rx_tx_tc(2, 246_257), Some(2.0));
    assert_eq!(rx_tx_tc(2, 492_512), Some(985_022.0));
    assert_eq!(rx_tx_tc(2, 0), None, "below the range");
    assert_eq!(rx_tx_tc(2, 492_513), None, "at or above the range");
    assert_eq!(rx_tx_tc(3, 246_256), Some(985_020.0));
    assert_eq!(rx_tx_tc(3, 246_257), None);
    // Each arm's open top value is its ASN.1 upper bound.
    for (k, top) in [
        (0, 1_970_049),
        (1, 985_025),
        (2, 492_513),
        (3, 246_257),
        (4, 123_129),
        (5, 61_565),
    ] {
        assert_eq!(rx_tx_tc(k, top), None, "k{k} top");
        assert!(rx_tx_tc(k, top - 1).is_some(), "k{k} top-1");
    }
}

/// Two halves of 326 Tc each make an RTT of 652 Tc = 331.6 ns, so the range is
/// c * RTT / 2 = 49.71 m.
#[test]
fn the_range_is_c_times_the_summed_halves_over_two() {
    let r = range_m(326.0, 326.0);
    assert!((r - 49.709).abs() < 0.01, "{r}");
    // The offset between the two UEs' transmissions cancels (TS 38.305 §8.15.2).
    let skew = 1000.0;
    assert!((range_m(326.0 + skew, 326.0 - skew) - r).abs() < 1e-9);
}

#[test]
fn a_range_needs_both_halves() {
    let store = SlRttStore::default();
    store.note(
        &UE_A,
        &[SlRttHalf {
            peer: UE_B.to_vec(),
            rx_tx_tc: 326.0,
        }],
    );
    assert_eq!(store.range_between(&UE_A, &UE_B), None, "one half only");
    store.note(
        &UE_B,
        &[SlRttHalf {
            peer: UE_A.to_vec(),
            rx_tx_tc: 326.0,
        }],
    );
    let ab = store.range_between(&UE_A, &UE_B).expect("both halves");
    assert!((ab - 49.709).abs() < 0.01, "{ab}");
    assert_eq!(store.range_between(&UE_B, &UE_A), Some(ab), "symmetric");
}

#[test]
fn a_stale_half_is_not_paired() {
    let store = SlRttStore::default();
    let then = Instant::now();
    let half = |peer: &[u8]| SlRttHalf {
        peer: peer.to_vec(),
        rx_tx_tc: 326.0,
    };
    store.note_at(&UE_A, &[half(&UE_B)], then);
    store.note_at(&UE_B, &[half(&UE_A)], then);
    assert!(store.range_between_at(&UE_A, &UE_B, then).is_some());
    let later = then + SL_RTT_HALF_MAX_AGE + Duration::from_secs(1);
    assert_eq!(store.range_between_at(&UE_A, &UE_B, later), None);
}

#[test]
fn the_store_is_capped_and_evicts_the_oldest() {
    let store = SlRttStore::default();
    let half = |n: usize| SlRttHalf {
        peer: n.to_be_bytes().to_vec(),
        rx_tx_tc: 1.0,
    };
    let first: Vec<SlRttHalf> = (0..SL_RTT_STORE_CAP).map(half).collect();
    store.note(&UE_A, &first);
    assert_eq!(store.len(), SL_RTT_STORE_CAP);
    store.note(&UE_A, &[half(SL_RTT_STORE_CAP)]);
    assert_eq!(store.len(), SL_RTT_STORE_CAP, "capped");
    // The oldest (peer 0) went; the newest is held.
    let s = store.inner.lock().unwrap();
    assert!(!s.halves.contains_key(&(UE_A.to_vec(), half(0).peer)));
    assert!(s
        .halves
        .contains_key(&(UE_A.to_vec(), half(SL_RTT_STORE_CAP).peer)));
}

#[test]
fn a_repeated_report_replaces_its_half_once() {
    let store = SlRttStore::default();
    let half = |t: f64| SlRttHalf {
        peer: UE_B.to_vec(),
        rx_tx_tc: t,
    };
    store.note(&UE_A, &[half(100.0)]);
    store.note(&UE_A, &[half(326.0)]);
    assert_eq!(store.len(), 1, "one record per (reporter, peer)");
    assert_eq!(store.inner.lock().unwrap().order.len(), 1);
}

#[test]
fn an_undecodable_message_is_a_header_error() {
    let e = decode_uplink(&[0xFF]).expect_err("one octet is not an SLPP-Message");
    assert_eq!(e.cause, ErrorCause::HeaderError);
    assert_eq!(e.tid, None);
}

/// A header that decodes around a container that does not is a body error on
/// that transaction (TS 38.355 §5.4.3).
#[test]
fn a_bad_container_is_a_body_error_on_its_transaction() {
    // The golden with its SL-RTT container replaced by one octet 0xFF: that
    // SEQUENCE's extension bit is set, and no extension follows it.
    let mut msg = nextgcore_slpp_gen::decode(&PROVIDE_CAPABILITIES).expect("golden");
    if let Some(g::SLPP_MessageBody::C1(g::SLPP_MessageBody_c1::ProvideCapabilities(pc))) =
        msg.slpp_message_body.as_mut()
    {
        let g::ProvideCapabilitiesCriticalExtensions::ProvideCapabilities(ies) =
            &mut pc.critical_extensions
        else {
            unreachable!()
        };
        ies.sl_rtt_provide_capabilities =
            Some(g::ProvideCapabilities_IEsSl_RTT_ProvideCapabilities(vec![
                0xFF,
            ]));
    }
    let bytes = nextgcore_slpp_gen::encode(&msg).expect("encodes");
    let e = decode_uplink(&bytes).expect_err("the container does not decode");
    assert_eq!(e.cause, ErrorCause::BodyError);
    assert_eq!(e.tid, Some(1));
}

#[test]
fn an_error_message_round_trips_as_ended() {
    let bytes = build_error(Some(9), Some(3), ErrorCause::BodyError).expect("builds");
    assert_eq!(
        decode_uplink(&bytes).expect("decodes"),
        Uplink::Ended {
            tid: Some(9),
            what: "Error"
        }
    );
    let msg = nextgcore_slpp_gen::decode(&bytes).expect("decodes");
    let Some(g::SLPP_MessageBody::C1(g::SLPP_MessageBody_c1::Error(g::Error::CriticalExtensions(
        g::Error_criticalExtensions::Error(ies),
    )))) = msg.slpp_message_body
    else {
        panic!("not an Error");
    };
    assert_eq!(ies.common_i_es_error.expect("cause").error_cause.0, 2);
}

#[test]
fn provide_assistance_data_ends_the_ues_transaction() {
    let bytes = build_provide_assistance_data(Some(4), None, Some(1)).expect("builds");
    let msg = nextgcore_slpp_gen::decode(&bytes).expect("decodes");
    assert_eq!(msg.transaction_id.map(|t| t.0), Some(4));
    assert!(
        msg.end_transaction.0,
        "the answer ends the UE's transaction"
    );
    assert!(matches!(
        msg.slpp_message_body,
        Some(g::SLPP_MessageBody::C1(
            g::SLPP_MessageBody_c1::ProvideAssistanceData(_)
        ))
    ));
}

#[tokio::test]
async fn an_answer_reaches_its_exchange_and_only_once() {
    static EX: OnceLock<SlppExchanges> = OnceLock::new();
    let ex = EX.get_or_init(SlppExchanges::default);
    let (_guard, rx) = ex.begin("imsi-1", 7).expect("begins");
    assert!(ex.begin("imsi-1", 7).is_none(), "one waiter per (UE, tid)");
    let answer = Uplink::Other { tid: Some(7) };
    assert!(
        !ex.complete("imsi-2", answer.clone()),
        "another UE's answer"
    );
    assert!(ex.complete("imsi-1", answer.clone()));
    assert_eq!(rx.await.expect("delivered"), answer);
    assert!(!ex.complete("imsi-1", answer), "a retry finds nothing");
}

#[tokio::test]
async fn a_dropped_exchange_leaves_nothing_waiting() {
    static EX: OnceLock<SlppExchanges> = OnceLock::new();
    let ex = EX.get_or_init(SlppExchanges::default);
    let (guard, _rx) = ex.begin("imsi-1", 3).expect("begins");
    assert_eq!(ex.pending(), 1);
    drop(guard);
    assert_eq!(ex.pending(), 0, "the guard removed its exchange");
    // A late guard cannot remove a newer exchange on the same key.
    let (old, _r1) = ex.begin("imsi-1", 3).expect("begins");
    let seq = old.seq;
    std::mem::forget(old);
    ex.waiting
        .lock()
        .unwrap()
        .remove(&("imsi-1".to_string(), 3));
    let (_new, _r2) = ex.begin("imsi-1", 3).expect("begins again");
    drop(ExchangeGuard {
        exchanges: ex,
        key: ("imsi-1".to_string(), 3),
        seq,
    });
    assert_eq!(ex.pending(), 1, "the newer exchange survives a stale guard");
}

#[test]
fn exchanges_are_capped() {
    static EX: OnceLock<SlppExchanges> = OnceLock::new();
    let ex = EX.get_or_init(SlppExchanges::default);
    let mut held = Vec::new();
    for i in 0..MAX_PENDING_EXCHANGES {
        held.push(ex.begin(&format!("ue-{i}"), 0).expect("under the cap"));
    }
    assert!(ex.begin("one-more", 0).is_none(), "capped");
}

/// TS 38.355 §4.3.2: the LMF's messages carry a sequence number.
/// RequestCapabilities on transaction 1 with sequenceNumber 0, hand-derived:
/// opts `0110010` (transactionID and sequenceNumber present) | tid `00000001` |
/// end `0` | sequenceNumber (0..255) `00000000` | then as
/// [`REQUEST_CAPABILITIES`]: c1 `0`, index `0000`, critExt `0`, IEs opts
/// `00010000`, len 1, `00000000`. That is 54 bits, plus 2 pad bits.
#[test]
fn the_lmf_stamps_a_sequence_number() {
    assert_eq!(
        build_request_capabilities(1, Some(0)).expect("builds"),
        [0x64, 0x02, 0x00, 0x00, 0x40, 0x04, 0x00]
    );
}

#[test]
fn sequence_numbers_are_distinct_per_ue_and_repeats_are_discarded() {
    let s = SlppSequences::default();
    let c = Some("corr-1");
    assert_eq!(s.next_sequence("ue-1", c), Some(0));
    assert_eq!(s.next_sequence("ue-1", c), Some(1));
    assert_eq!(s.next_sequence("ue-2", c), Some(0), "per UE");
    assert!(!s.is_duplicate("ue-1", c, Some(5)));
    assert!(
        s.is_duplicate("ue-1", c, Some(5)),
        "the same number again is discarded"
    );
    assert!(
        !s.is_duplicate("ue-2", c, Some(5)),
        "another UE's number is its own"
    );
    assert!(!s.is_duplicate("ue-1", c, Some(6)));
    assert!(
        !s.is_duplicate("ue-1", c, None),
        "no number, nothing to compare"
    );
    assert!(!s.is_duplicate("ue-1", c, None));
}

/// TS 38.355 §4.3.2: sequence numbers belong to a location session. A new
/// session starts its own, and the server deletes a session's numbers when it
/// ends.
#[test]
fn sequence_numbers_are_per_location_session_and_end_with_it() {
    let s = SlppSequences::default();
    assert_eq!(s.next_sequence("ue-1", Some("a")), Some(0));
    assert_eq!(s.next_sequence("ue-1", Some("a")), Some(1));
    assert_eq!(s.next_sequence("ue-1", Some("b")), Some(0), "per session");
    assert!(!s.is_duplicate("ue-1", Some("a"), Some(0)));
    assert!(
        !s.is_duplicate("ue-1", Some("b"), Some(0)),
        "seq 0 of another session is not a duplicate"
    );
    assert!(s.is_duplicate("ue-1", Some("a"), Some(0)));
    s.end_session("ue-1", Some("a"));
    assert!(!s.tracks("ue-1", Some("a")), "deleted at the session's end");
    assert!(s.tracks("ue-1", Some("b")), "the other session is kept");
    assert_eq!(s.next_sequence("ue-1", Some("a")), Some(0));
    assert!(!s.is_duplicate("ue-1", Some("a"), Some(0)));
}

/// The session guard of a SL-RTT run deletes its numbers on any exit.
#[tokio::test]
async fn a_finished_sl_rtt_session_deletes_its_sequence_numbers() {
    let _g = SLPP_GLOBALS_TEST_LOCK.lock().await;
    let ue = "imsi-001010000557901";
    let a = SessionGuard::begin(ue).expect("live");
    let b = SessionGuard::begin(ue).expect("live");
    assert_ne!(a.correlation_id(), b.correlation_id(), "one id per session");
    let corr = a.correlation_id().to_string();
    assert_eq!(sequences().next_sequence(ue, Some(&corr)), Some(0));
    assert!(!sequences().is_duplicate(ue, Some(&corr), Some(3)));
    drop(a);
    assert!(!sequences().tracks(ue, Some(&corr)));
}

/// A bare acknowledgement of sequence number 1 (TS 38.355 §4.3.3), hand-derived:
/// opts `0000100` (acknowledgement only) | end `0` | Acknowledgement opts `1` |
/// ackRequested `0` | ackIndicator `00000001`. That is 18 bits, plus 6 pad
/// bits. No transactionID and no sequenceNumber without a body (§6.2).
#[test]
fn a_bare_acknowledgement_is_the_hand_derived_octets() {
    assert_eq!(build_ack(1).expect("builds"), [0x08, 0x80, 0x40]);
    let msg = nextgcore_slpp_gen::decode(&[0x08, 0x80, 0x40]).expect("decodes");
    assert_eq!(msg.sequence_number, None);
    assert_eq!(msg.transaction_id, None);
    assert!(msg.slpp_message_body.is_none());
}

/// §5.2.5: the answer carries the received sessionID and transactionID, and no
/// transactionID when the request had none.
#[test]
fn provide_assistance_data_echoes_the_session_and_the_transaction() {
    let session = vec![1, 2, 3, 4, 5, 6];
    let msg = nextgcore_slpp_gen::decode(
        &build_provide_assistance_data(Some(4), Some(session.clone()), Some(1)).expect("builds"),
    )
    .expect("decodes");
    assert_eq!(msg.session_id.map(|s| s.0), Some(session));
    assert_eq!(msg.transaction_id.map(|t| t.0), Some(4));
    let msg = nextgcore_slpp_gen::decode(
        &build_provide_assistance_data(None, None, Some(1)).expect("builds"),
    )
    .expect("decodes");
    assert_eq!(msg.transaction_id, None, "no invented transaction 0");
    assert_eq!(msg.session_id, None);
}

/// A UE RequestAssistanceData with `seq`, a sessionID, and an acknowledgement
/// request when `ack`.
fn ue_assistance_request(tid: Option<u8>, seq: u8, ack: bool) -> Vec<u8> {
    nextgcore_slpp_gen::encode(&g::SLPP_Message {
        application_layer_id: Some(g::SLPP_MessageApplicationLayerID(UE_A.to_vec())),
        transaction_id: tid.map(g::SLPP_MessageTransactionID),
        end_transaction: g::SLPP_MessageEndTransaction(false),
        sequence_number: Some(g::SequenceNumber(seq)),
        session_id: Some(g::SessionID(vec![9; 6])),
        acknowledgement: ack.then_some(g::Acknowledgement {
            ack_requested: g::AcknowledgementAckRequested(true),
            ack_indicator: None,
        }),
        slpp_message_body: Some(g::SLPP_MessageBody::C1(
            g::SLPP_MessageBody_c1::RequestAssistanceData(g::RequestAssistanceData {
                critical_extensions:
                    g::RequestAssistanceDataCriticalExtensions::CriticalExtensionsFuture(
                        g::RequestAssistanceDataCriticalExtensions_criticalExtensionsFuture {},
                    ),
            }),
        )),
        non_critical_extension: None,
    })
    .expect("encodes")
}

/// §4.3.3 and §4.3.4.2 step 4 at the handler: a message asking for an
/// acknowledgement gets a bare one first, and a duplicate still gets one but
/// nothing else.
#[tokio::test]
async fn the_handler_acknowledges_every_copy_that_asks() {
    let _g = SLPP_GLOBALS_TEST_LOCK.lock().await;
    let ue = "imsi-001010000557902";
    let corr = Some("corr-ack");
    let req = ue_assistance_request(Some(7), 4, true);
    let first = crate::slpp_uplink_answers(ue, corr, &req);
    assert_eq!(
        first.len(),
        2,
        "acknowledgement, then ProvideAssistanceData"
    );
    let ack = nextgcore_slpp_gen::decode(&first[0]).expect("decodes");
    assert_eq!(
        ack.acknowledgement
            .and_then(|a| a.ack_indicator)
            .map(|s| s.0),
        Some(4)
    );
    assert_eq!(ack.sequence_number, None, "§6.2: none without a body");
    let pad = nextgcore_slpp_gen::decode(&first[1]).expect("decodes");
    assert_eq!(pad.transaction_id.map(|t| t.0), Some(7));
    assert_eq!(pad.session_id.map(|s| s.0), Some(vec![9; 6]), "§5.2.5");

    let repeat = crate::slpp_uplink_answers(ue, corr, &req);
    assert_eq!(
        repeat.len(),
        1,
        "the duplicate gets only its acknowledgement"
    );
    assert_eq!(repeat[0], first[0]);

    // Without the request, nothing acknowledges.
    let plain = crate::slpp_uplink_answers(ue, corr, &ue_assistance_request(None, 5, false));
    assert_eq!(plain.len(), 1);
    let pad = nextgcore_slpp_gen::decode(&plain[0]).expect("decodes");
    assert!(pad.acknowledgement.is_none());
    assert_eq!(pad.transaction_id, None, "none received, none sent");
    sequences().end_session(ue, corr);
}

/// §4.3.2 at the handler: the duplicate check is per location session, so the
/// same sequence number under another LCS correlation id is processed.
#[tokio::test]
async fn the_handler_checks_duplicates_per_location_session() {
    let _g = SLPP_GLOBALS_TEST_LOCK.lock().await;
    let ue = "imsi-001010000557903";
    let req = ue_assistance_request(Some(1), 0, false);
    assert_eq!(crate::slpp_uplink_answers(ue, Some("s-1"), &req).len(), 1);
    assert_eq!(
        crate::slpp_uplink_answers(ue, Some("s-2"), &req).len(),
        1,
        "seq 0 of another session is answered"
    );
    assert!(
        crate::slpp_uplink_answers(ue, Some("s-1"), &req).is_empty(),
        "a repeat within s-1 is discarded"
    );
    sequences().end_session(ue, Some("s-1"));
    sequences().end_session(ue, Some("s-2"));
}

/// The cross-repo pin: nextgsim's UE answers lmfd's REQUEST_CAPABILITIES with
/// these octets (nextgsim #592, `UE_PROVIDE_CAPABILITIES` in
/// nextgsim-ue/src/nas/slpp/tests.rs). They carry the UE's sequenceNumber, and
/// a band reporting n1.
#[test]
fn the_nextgsim_ue_capability_reply_decodes() {
    assert_eq!(
        decode_uplink_with_sequence(&NEXTGSIM_UE_PROVIDE_CAPABILITIES).expect("decodes"),
        (
            Uplink::Capabilities {
                tid: Some(1),
                app_id: Some(UE_A.to_vec()),
                sl_rtt_ue_assisted: true,
            },
            Some(0)
        )
    );
}

/// The cross-repo pin: nextgsim's UE answers REQUEST_LOCATION_INFORMATION with
/// these octets (`UE_PROVIDE_LOCATION_INFORMATION`, #592). That is one SL-RTT half
/// on 5A5A5A for a peer at 50 m, whose one-way flight time is 50 / c =
/// 166.78 ns = 327.9 Tc. The bin midpoint is within 2 Tc of that.
#[test]
fn the_nextgsim_ue_location_reply_decodes_to_a_50_m_half() {
    let (uplink, seq) =
        decode_uplink_with_sequence(&NEXTGSIM_UE_PROVIDE_LOCATION_INFORMATION).expect("decodes");
    assert_eq!(seq, Some(1));
    let Uplink::Location {
        tid,
        app_id,
        halves,
        sl_rtt_error,
    } = uplink
    else {
        panic!("not a location report");
    };
    assert_eq!(
        (tid, app_id, sl_rtt_error),
        (Some(2), Some(UE_A.to_vec()), None)
    );
    assert_eq!(halves.len(), 1);
    assert_eq!(halves[0].peer, UE_B);
    let flight_tc = 50.0 / SPEED_OF_LIGHT_M_S / TC_SECONDS;
    assert!(
        (halves[0].rx_tx_tc - flight_tc).abs() <= 2.0,
        "{} vs {flight_tc}",
        halves[0].rx_tx_tc
    );
}

/// TS 38.355 §4.3.2 at the notify handler. A message that repeats the UE's
/// last sequence number is discarded: it neither completes an exchange nor
/// adds a half. The same message with the next sequence number is taken.
#[tokio::test]
async fn the_notify_handler_discards_a_repeated_sequence_number() {
    let _g = SLPP_GLOBALS_TEST_LOCK.lock().await;
    let ue = "imsi-001010000557900";
    let owner = crate::context::NotifyOwner::ue(ue);
    let first = NEXTGSIM_UE_PROVIDE_LOCATION_INFORMATION.to_vec();
    let (_g1, rx1) = exchanges().begin(ue, 2).expect("begins");
    assert_eq!(
        crate::handle_slpp_uplink(&owner, None, first.clone())
            .await
            .status,
        204
    );
    assert!(rx1.await.is_ok(), "the first copy answers its exchange");

    let (_g2, mut rx2) = exchanges().begin(ue, 2).expect("begins again");
    crate::handle_slpp_uplink(&owner, None, first).await;
    assert!(rx2.try_recv().is_err(), "the repeat is discarded");

    let mut msg = nextgcore_slpp_gen::decode(&NEXTGSIM_UE_PROVIDE_LOCATION_INFORMATION).unwrap();
    msg.sequence_number = Some(g::SequenceNumber(2));
    crate::handle_slpp_uplink(&owner, None, nextgcore_slpp_gen::encode(&msg).unwrap()).await;
    assert!(rx2.try_recv().is_ok(), "the next sequence number is taken");
}

/// R45 M2 on #2254: the halves are signed, so a pair can sum below zero. That is
/// no distance (TS 29.572's is a magnitude), and neither is a non-finite one.
#[test]
fn a_negative_or_non_finite_range_is_no_range() {
    assert_eq!(valid_range_m(-5000.0, 100.0), None, "-373.6 m");
    assert_eq!(valid_range_m(f64::NAN, 1.0), None);
    assert_eq!(valid_range_m(f64::INFINITY, 1.0), None);
    let r = valid_range_m(326.0, 330.0).expect("a distance");
    assert!((r - range_m(326.0, 330.0)).abs() < 1e-9 && r > 0.0);
    assert!(
        valid_range_m(985_024.0, 985_024.0).is_some(),
        "the top is a range"
    );
    let s = SlRttStore::default();
    s.note(
        &UE_A,
        &[SlRttHalf {
            peer: UE_B.to_vec(),
            rx_tx_tc: -5000.0,
        }],
    );
    s.note(
        &UE_B,
        &[SlRttHalf {
            peer: UE_A.to_vec(),
            rx_tx_tc: 100.0,
        }],
    );
    assert_eq!(s.range_between(&UE_A, &UE_B), None, "never reported");
}

/// R45 M3 on #2254: a full map never loses a live session's counter. Other
/// sessions go oldest first, and idle ones expire.
#[test]
fn a_live_session_survives_the_cap_and_idle_ones_expire() {
    let s = SlppSequences::default();
    let t0 = Instant::now();
    assert!(s.begin_live("imsi-live", "live"));
    assert_eq!(s.next_sequence_at("imsi-live", Some("live"), t0), Some(0));
    for i in 0..MAX_PENDING_EXCHANGES + 10 {
        let at = t0 + Duration::from_millis(i as u64 + 1);
        s.next_sequence_at(&format!("imsi-{i}"), None, at);
    }
    assert_eq!(
        s.next_sequence_at("imsi-live", Some("live"), t0 + Duration::from_secs(1)),
        Some(1),
        "the live session's counter goes on"
    );
    assert!(!s.tracks("imsi-0", None), "the oldest other one went");
    assert!(s.tracks(&format!("imsi-{}", MAX_PENDING_EXCHANGES + 9), None));
    let len = s.inner.lock().unwrap().sent.len();
    assert!(len <= MAX_PENDING_EXCHANGES + 1, "bounded: {len}");

    // Idle for SESSION_IDLE: forgotten when room is needed.
    let later = t0 + SESSION_IDLE + Duration::from_secs(5);
    s.next_sequence_at("imsi-new", None, later);
    let left = s.inner.lock().unwrap().sent.len();
    assert_eq!(left, 2, "the live session and the new one");

    // The same for the received side.
    for i in 0..MAX_PENDING_EXCHANGES + 10 {
        s.is_duplicate_at(&format!("imsi-r{i}"), None, Some(0), t0);
    }
    assert!(s.inner.lock().unwrap().received.len() <= MAX_PENDING_EXCHANGES);
    s.end_session("imsi-live", Some("live"));
    assert!(!s
        .inner
        .lock()
        .unwrap()
        .live
        .contains(&session_key("imsi-live", Some("live"))));
}

/// Live sessions are themselves capped.
#[test]
fn live_sessions_are_capped() {
    let s = SlppSequences::default();
    for i in 0..MAX_PENDING_EXCHANGES {
        assert!(s.begin_live("ue", &format!("s-{i}")));
    }
    assert!(!s.begin_live("ue", "one-more"));
}

/// R45 M1 on #2254: an applicationLayerID is its first claimer's. Another UE
/// cannot take it while that binding is in use, and an idle binding expires.
#[test]
fn an_application_layer_id_is_bound_to_its_first_ue() {
    let b = AppIdBindings::default();
    let t0 = Instant::now();
    assert!(b.claim_at(&UE_A, "imsi-a", t0));
    assert!(b.claim_at(&UE_A, "imsi-a", t0), "its own again");
    assert!(!b.claim_at(&UE_A, "imsi-mallory", t0), "not another UE's");
    assert!(b.is_bound_to(&UE_A, "imsi-a"));
    assert!(!b.is_bound_to(&UE_A, "imsi-mallory"));
    assert!(
        b.claim_at(&UE_A, "imsi-other", t0 + APP_ID_BINDING_IDLE),
        "free again once idle"
    );
}

/// ProvideLocationInformation from UE A5A5A5 with `seq`: the golden, re-numbered.
fn located(seq: u8) -> Vec<u8> {
    let mut m = nextgcore_slpp_gen::decode(&PROVIDE_LOCATION_INFORMATION).unwrap();
    m.sequence_number = Some(g::SequenceNumber(seq));
    nextgcore_slpp_gen::encode(&m).unwrap()
}

/// R45 M1 on #2254 at the handler, R45's probe: a UE that forges A5A5A5's report
/// gets nothing held, solicited or not. The honest UE's answer to an exchange
/// is held, and an unsolicited one is not.
#[tokio::test]
async fn only_solicited_halves_under_the_ue_s_own_id_are_held() {
    let _g = SLPP_GLOBALS_TEST_LOCK.lock().await;
    let honest = "imsi-001010000557910";
    let mallory = "imsi-001010000557911";
    app_id_bindings().forget(&UE_A);
    sl_rtt_store().clear();
    let peer_half = |s: &SlRttStore| {
        s.note(
            &UE_B,
            &[SlRttHalf {
                peer: UE_A.to_vec(),
                rx_tx_tc: 330.0,
            }],
        );
    };
    peer_half(sl_rtt_store());

    // Unsolicited, from anyone: not held.
    crate::slpp_uplink_answers(mallory, Some("m-1"), &located(1));
    assert_eq!(
        sl_rtt_store().range_between(&UE_A, &UE_B),
        None,
        "unsolicited"
    );

    // The honest UE answers its exchange: held, and A5A5A5 is now its.
    let (_g1, rx) = exchanges().begin(honest, 2).expect("begins");
    crate::slpp_uplink_answers(honest, Some("h-1"), &located(1));
    assert!(rx.await.is_ok());
    assert!(app_id_bindings().is_bound_to(&UE_A, honest));
    let honest_range = sl_rtt_store().range_between(&UE_A, &UE_B).expect("held");

    // Mallory, in an exchange of its own, claims A5A5A5 with a different half.
    let mut forged = nextgcore_slpp_gen::decode(&located(2)).unwrap();
    let g::SLPP_MessageBody::C1(g::SLPP_MessageBody_c1::ProvideLocationInformation(p)) =
        forged.slpp_message_body.as_mut().unwrap()
    else {
        unreachable!()
    };
    let g::ProvideLocationInformationCriticalExtensions::ProvideLocationInformation(ies) =
        &mut p.critical_extensions
    else {
        unreachable!()
    };
    let mut rtt: g::SL_RTT_ProvideLocationInformation =
        nextgcore_slpp_gen::decode_ie(&ies.sl_rtt_provide_location_information.as_ref().unwrap().0)
            .unwrap();
    let el = &mut rtt
        .sl_rtt_signal_measurement_information
        .as_mut()
        .unwrap()
        .sl_rtt_meas_list
        .0[0]
        .0[0];
    let g::SL_PRS_RxTxTimeDiffMeasResult::Single_SL_PRS_RxTxTimeDiff(r) =
        &mut el.sl_prs_rx_tx_time_diff_meas_result
    else {
        unreachable!()
    };
    r.sl_prs_rx_tx_time_diff_result =
        Some(g::SL_PRS_RxTxTimeDiffResultSl_PRS_RxTxTimeDiffResult::K2(
            g::SL_PRS_RxTxTimeDiffResultSl_PRS_RxTxTimeDiffResult_k2(250_000),
        ));
    ies.sl_rtt_provide_location_information = Some(
        g::ProvideLocationInformation_IEsSl_RTT_ProvideLocationInformation(
            nextgcore_slpp_gen::encode_ie(&rtt).unwrap(),
        ),
    );
    let (_g2, rx) = exchanges().begin(mallory, 2).expect("begins");
    crate::slpp_uplink_answers(
        mallory,
        Some("m-2"),
        &nextgcore_slpp_gen::encode(&forged).unwrap(),
    );
    assert!(rx.await.is_ok(), "its exchange is still answered");
    assert_eq!(
        sl_rtt_store().range_between(&UE_A, &UE_B),
        Some(honest_range),
        "the forged half is not held"
    );
    // And Mallory, ranged as if it were A5A5A5, is not given A5A5A5's range.
    assert_eq!(range_for(honest, &UE_A, &UE_B), Some(honest_range));
    assert_eq!(range_for(mallory, &UE_A, &UE_B), None, "not Mallory's ID");
    app_id_bindings().forget(&UE_A);
    for s in ["m-1", "h-1", "m-2"] {
        sequences().end_session(honest, Some(s));
        sequences().end_session(mallory, Some(s));
    }
}
