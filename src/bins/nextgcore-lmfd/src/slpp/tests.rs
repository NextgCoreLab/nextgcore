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
    let bytes = build_provide_assistance_data(4, Some(1)).expect("builds");
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
    assert_eq!(s.next_sequence("ue-1"), Some(0));
    assert_eq!(s.next_sequence("ue-1"), Some(1));
    assert_eq!(s.next_sequence("ue-2"), Some(0), "per UE");
    assert!(!s.is_duplicate("ue-1", Some(5)));
    assert!(
        s.is_duplicate("ue-1", Some(5)),
        "the same number again is discarded"
    );
    assert!(
        !s.is_duplicate("ue-2", Some(5)),
        "another UE's number is its own"
    );
    assert!(!s.is_duplicate("ue-1", Some(6)));
    assert!(
        !s.is_duplicate("ue-1", None),
        "no number, nothing to compare"
    );
    assert!(!s.is_duplicate("ue-1", None));
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
