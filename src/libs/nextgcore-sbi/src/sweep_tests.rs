//! #2186: the shared bounded per-peer sweep.

use super::*;
use std::sync::atomic::AtomicUsize;
use std::sync::Mutex;

const DEAD: &str = "dead";
const LIVE: &str = "live";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

fn limits(per_peer: usize, global: usize, budget: Duration) -> SweepLimits {
    SweepLimits {
        per_peer,
        global,
        budget,
    }
}

/// The issue's test: one dead peer (every call hangs for the request timeout,
/// then fails) with many items, and one healthy peer with one item whose
/// deadline is 1 s out. The healthy item meets its deadline, and the dead peer
/// costs `per_peer` timeouts, its other items parked.
///
/// REVERT-VERIFIED: with the parking ignored the dead peer's 200 items take 100
/// timeouts; with the peers run in turn the healthy item waits behind them.
#[tokio::test(start_paused = true)]
async fn a_dead_peer_does_not_hold_a_healthy_peer_past_its_deadline() {
    let t0 = tokio::time::Instant::now();
    let finished: Arc<Mutex<Option<Duration>>> = Arc::default();
    let mut items: Vec<(&'static str, u32)> = (0..200).map(|n| (DEAD, n)).collect();
    items.push((LIVE, 0));
    let f = finished.clone();
    let report = sweep(
        limits(2, 4, Duration::from_secs(60)),
        items,
        Instant::now,
        move |peer, _n, _now| {
            let f = f.clone();
            async move {
                if peer == DEAD {
                    tokio::time::sleep(REQUEST_TIMEOUT).await;
                    (Verdict::PeerDown, ())
                } else {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                    *f.lock().unwrap() = Some(t0.elapsed());
                    (Verdict::Answered, ())
                }
            }
        },
    )
    .await;
    let live_at = finished.lock().unwrap().expect("the healthy item ran");
    assert!(
        live_at < Duration::from_secs(1),
        "met its deadline: {live_at:?}"
    );
    let dead_done = report.done.iter().filter(|(k, _)| *k == DEAD).count();
    assert_eq!(dead_done, 2, "per_peer timeouts, then parked");
    assert_eq!(report.skipped_for(Skip::PeerParked), 198);
    assert!(t0.elapsed() < REQUEST_TIMEOUT * 2, "{:?}", t0.elapsed());
}

/// Items not started when the budget runs out are the next pass's.
///
/// REVERT-VERIFIED: without the budget check all five run.
#[tokio::test(start_paused = true)]
async fn the_budget_stops_new_items_and_skips_the_rest() {
    let report = sweep(
        limits(1, 8, Duration::from_millis(2500)),
        (0..5u32).map(|n| ("p", n)),
        Instant::now,
        |_, n, _| async move {
            tokio::time::sleep(Duration::from_secs(1)).await;
            (Verdict::Answered, n)
        },
    )
    .await;
    let done: Vec<u32> = report.done.iter().map(|(_, n)| *n).collect();
    assert_eq!(done, vec![0, 1, 2], "started at 0, 1 and 2 s");
    let skipped: Vec<u32> = report.skipped.iter().map(|(_, n, _)| *n).collect();
    assert_eq!(skipped, vec![3, 4]);
    assert_eq!(report.skipped_for(Skip::Budget), 2);
}

/// The clock is read per item, when it starts, not once per pass.
///
/// REVERT-VERIFIED: with the clock read once before the loop every item sees 0.
#[tokio::test(start_paused = true)]
async fn the_clock_is_read_afresh_for_each_item() {
    let t0 = tokio::time::Instant::now();
    let report = sweep(
        limits(1, 1, Duration::from_secs(60)),
        (0..3u32).map(|n| ("p", n)),
        move || t0.elapsed().as_secs(),
        |_, _, now| async move {
            tokio::time::sleep(Duration::from_secs(1)).await;
            (Verdict::Answered, now)
        },
    )
    .await;
    let nows: Vec<u64> = report.done.iter().map(|(_, n)| *n).collect();
    assert_eq!(nows, vec![0, 1, 2]);
}

/// Never more than `per_peer` of a peer's items, nor `global` in all, at once.
///
/// REVERT-VERIFIED: without the global semaphore 3 peers x 2 run at once.
#[tokio::test(start_paused = true)]
async fn concurrency_is_bounded_per_peer_and_globally() {
    #[derive(Default)]
    struct Gauge {
        now: AtomicUsize,
        max: AtomicUsize,
    }
    impl Gauge {
        fn enter(&self) {
            let n = self.now.fetch_add(1, Ordering::SeqCst) + 1;
            self.max.fetch_max(n, Ordering::SeqCst);
        }
        fn leave(&self) {
            self.now.fetch_sub(1, Ordering::SeqCst);
        }
    }
    let all = Arc::new(Gauge::default());
    let per: Arc<[Gauge; 3]> = Arc::new(Default::default());
    let (a, p) = (all.clone(), per.clone());
    let items = (0..30u32).map(|n| ((n % 3) as usize, n));
    let report = sweep(
        limits(2, 4, Duration::from_secs(600)),
        items,
        Instant::now,
        move |peer, _, _| {
            let (a, p) = (a.clone(), p.clone());
            async move {
                a.enter();
                p[peer].enter();
                tokio::time::sleep(Duration::from_millis(100)).await;
                p[peer].leave();
                a.leave();
                (Verdict::Answered, ())
            }
        },
    )
    .await;
    assert_eq!(report.done.len(), 30);
    assert_eq!(
        all.max.load(Ordering::SeqCst),
        4,
        "global bound reached, not passed"
    );
    for g in per.iter() {
        assert!(g.max.load(Ordering::SeqCst) <= 2);
    }
}

/// Results come back per peer in key order, each peer's in input order, and an
/// answer that is not `PeerDown` keeps the peer going.
#[tokio::test(start_paused = true)]
async fn results_keep_the_input_order_per_peer() {
    let items = vec![("b", 1u32), ("a", 2), ("b", 3), ("a", 4)];
    let report = sweep(
        limits(4, 4, Duration::from_secs(60)),
        items,
        Instant::now,
        |_, n, _| async move {
            // Later items finish first.
            tokio::time::sleep(Duration::from_millis(100 - n as u64)).await;
            (Verdict::Answered, n)
        },
    )
    .await;
    assert_eq!(report.done, vec![("a", 2), ("a", 4), ("b", 1), ("b", 3)]);
    assert!(report.skipped.is_empty());
}

/// Dropping the pass aborts its in-flight items: nothing outlives it.
///
/// REVERT-VERIFIED: with the items spawned detached (`tokio::spawn`), they run
/// to completion after the drop.
#[tokio::test(start_paused = true)]
async fn a_dropped_pass_leaves_nothing_running() {
    let completed = Arc::new(AtomicUsize::new(0));
    let c = completed.clone();
    let pass = sweep(
        limits(4, 4, Duration::from_secs(60)),
        (0..4u32).map(|n| (n, n)),
        Instant::now,
        move |_, _, _| {
            let c = c.clone();
            async move {
                tokio::time::sleep(Duration::from_secs(1)).await;
                c.fetch_add(1, Ordering::SeqCst);
                (Verdict::Answered, ())
            }
        },
    );
    let _ = tokio::time::timeout(Duration::from_millis(100), pass).await;
    tokio::time::sleep(Duration::from_secs(5)).await;
    assert_eq!(completed.load(Ordering::SeqCst), 0);
}

/// Zero limits are taken as 1, not as a pass that never starts anything.
#[tokio::test(start_paused = true)]
async fn zero_limits_mean_one() {
    let report = sweep(
        limits(0, 0, Duration::from_secs(60)),
        vec![("p", 1u32), ("q", 2)],
        Instant::now,
        |_, n, _| async move { (Verdict::Answered, n) },
    )
    .await;
    assert_eq!(report.done.len(), 2);
}

/// #2186 (R44): peers start in a rotated order each pass, so with more dead
/// peers ahead than the budget covers a given peer is still first in some
/// pass. Here only the first-started peer runs per pass (global 1, budget
/// shorter than one item); over 30 passes more than one peer gets to run.
///
/// REVERT-VERIFIED: with the rotation offset 0 (key order), peer "a" runs in
/// every pass.
#[tokio::test(start_paused = true)]
async fn the_start_order_rotates_between_passes() {
    let mut first = std::collections::BTreeSet::new();
    for _ in 0..30 {
        let report = sweep(
            limits(1, 1, Duration::from_millis(500)),
            vec![("a", 0u8), ("b", 0), ("c", 0)],
            Instant::now,
            |_, _, _| async {
                tokio::time::sleep(Duration::from_secs(1)).await;
                (Verdict::Answered, ())
            },
        )
        .await;
        assert_eq!(report.done.len(), 1, "one item per pass");
        first.insert(report.done[0].0);
    }
    assert!(first.len() > 1, "always the same peer first: {first:?}");
}

/// #2223 (R41 on #2240): [`with_start_offset`] pins the start order: with
/// only the first-started peer running per pass, the pinned one runs in every
/// pass, and the pin is this task's only.
///
/// REVERT-VERIFIED: with `pinned_offset` always `None`, "c" is not first in
/// every pass.
#[tokio::test(start_paused = true)]
async fn a_pinned_start_offset_fixes_the_first_peer() {
    for _ in 0..30 {
        let report = with_start_offset(
            2,
            sweep(
                limits(1, 1, Duration::from_millis(500)),
                vec![("a", 0u8), ("b", 0), ("c", 0)],
                Instant::now,
                |_, _, _| async {
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    (Verdict::Answered, ())
                },
            ),
        )
        .await;
        assert_eq!(report.done.len(), 1);
        assert_eq!(report.done[0].0, "c", "index 2 of the key order starts");
    }
}

/// #2223: [`retry_parked`] around the backoff. A peer backing off when the
/// pass begins is not started (its work never runs) and takes no slot; a dead
/// peer costs one item and is noted failed once; a live one is noted
/// succeeded; an item not sent (`None`) tells the backoff nothing; every item
/// comes back in batch order, `None` for the ones not started.
///
/// REVERT-VERIFIED: with the backoff filter dropped, the backing-off peer's
/// work runs ("not tried while backing off"); with the notes dropped, "dead
/// backs off" fails.
#[tokio::test(start_paused = true)]
async fn retry_parked_filters_and_feeds_the_backoff() {
    let backoff = PeerBackoff::new(Duration::from_secs(30), Duration::from_secs(600));
    backoff.note_failure("off");
    let ran: Arc<Mutex<Vec<u32>>> = Arc::default();
    let seen = ran.clone();
    let batch: Vec<(String, u32)> = vec![
        ("off".into(), 1),
        (DEAD.into(), 2),
        (DEAD.into(), 3),
        (LIVE.into(), 4),
        ("quiet".into(), 5),
    ];
    let out = retry_parked(
        &backoff,
        limits(1, 1, Duration::from_secs(60)),
        batch,
        move |peer, n| {
            let seen = seen.clone();
            async move {
                seen.lock().unwrap().push(n);
                match peer.as_str() {
                    DEAD => {
                        tokio::time::sleep(REQUEST_TIMEOUT).await;
                        (Some(Verdict::PeerDown), n, "down")
                    }
                    LIVE => (Some(Verdict::Answered), n, "ok"),
                    _ => (None, n, "not sent"),
                }
            }
        },
    )
    .await;
    assert_eq!(
        out,
        vec![
            (1, None),
            (2, Some("down")),
            (3, None),
            (4, Some("ok")),
            (5, Some("not sent")),
        ]
    );
    let mut ran = ran.lock().unwrap().clone();
    ran.sort();
    assert_eq!(ran, vec![2, 4, 5], "not tried while backing off");
    assert!(backoff.backing_off(DEAD), "dead backs off");
    assert_eq!(backoff.current(DEAD), Some(Duration::from_secs(30)), "once");
    assert_eq!(backoff.current(LIVE), None);
    assert_eq!(backoff.current("quiet"), None, "not sent: no entry");
    assert_eq!(backoff.current("off"), Some(Duration::from_secs(30)));
}

/// Why a flagged fn is not a hand-rolled peer sweep (or is one still to move).
const TIMER: &str = "a timer loop that drives a pass; the pass is checked on its own";
const PROCEDURE: &str = "one request's or one UE's procedure, not a periodic pass over peers";
const SHUTDOWN: &str =
    "a shutdown drain that waits, bounded by the shutdown budget, for tasks already in flight";
const ONE_PEER: &str = "every call goes to one peer, so no peer can hold another back";
const CONCURRENT: &str =
    "all calls already run at once on a JoinSet, each bounded by its own timeout";
const LOCAL: &str = "no remote call per peer in the loop";
/// #2223: a reconciler of parked work whose every item goes to the one peer it
/// resolves (tsctsf's PCF, pcfd's BSF): its first failure ends or backs off the
/// pass, and there is no other peer to hold back.
const ONE_RESOLVED_PEER: &str =
    "every parked item goes to the one peer resolved for the pass; a failure stops the pass";

// Known limits of the guard, a name-and-syntax heuristic (#2216 R41, #2223):
//
// - G1, a pass fn plus a helper: `refresh_all_legs` calling a `send_each`
//   (no pass word) that loops and awaits is not flagged. Following a pass
//   fn's same-crate callees was tried (#2223) and flagged 35 more fns on main,
//   every one checked a per-UE or per-request procedure (or a callee already
//   allowed, such as lmfd's concurrent `unsubscribe_all`), so it would mostly
//   grow this list.
// - G2, the pass word only in the type: `impl LegRefresher { async fn run() }`
//   is not flagged.
// - A fn that calls `sweep::sweep(` or `sweep::retry_parked(` is exempt as a
//   whole, so a serial loop beside the call is not flagged (#2223 R48; the
//   self-test's `reconcile_on_retry_parked` plants one).
// - A fn is cut at the next `fn `, so a closure-heavy body or a nested fn can
//   move a loop to the fn after it.
//
// Review a new periodic pass against `sweep` by hand as well.

/// Every production fn the guard flags today: (file, fn name, how many fns of
/// that name in the file the guard flags, the reason it is not (yet) a shared
/// sweep). A NEW flagged fn fails `no_hand_rolled_sweeps_remain`, and so does a
/// second one of an allowed name in the same file (#2216 R41 F1): the count is
/// the one the entry was written for.
const ALLOWED: &[(&str, &str, usize, &str)] = &[
    ("nextgcore-smfd/src/main.rs", "gsm_expiry_permits", 1, LOCAL),
    (
        "nextgcore-amfd/src/nrf_subscription.rs",
        "unsubscribe_all",
        1,
        CONCURRENT,
    ),
    (
        "nextgcore-amfd/src/nsac.rs",
        "a_cancelled_admission_leaves_its_slot_and_parks_what_it_owed_2036",
        1,
        PROCEDURE,
    ),
    ("nextgcore-amfd/src/nsac.rs", "spawn_reconciler", 1, TIMER),
    (
        "nextgcore-amfd/src/ngap_path.rs",
        "apply_release_complete",
        1,
        PROCEDURE,
    ),
    (
        "nextgcore-amfd/src/ngap_path.rs",
        "handle_ue_context_release",
        1,
        PROCEDURE,
    ),
    (
        "nextgcore-amfd/src/ngap_path.rs",
        "offload_release_held_sessions",
        1,
        PROCEDURE,
    ),
    (
        "nextgcore-amfd/src/ngap_path.rs",
        "offload_superseded_releases",
        1,
        PROCEDURE,
    ),
    (
        "nextgcore-amfd/src/ngap_path.rs",
        "process_pending_source_releases",
        1,
        PROCEDURE,
    ),
    (
        "nextgcore-amfd/src/ngap_path.rs",
        "process_release_guards",
        1,
        PROCEDURE,
    ),
    (
        "nextgcore-amfd/src/ngap_path.rs",
        "reconcile_update_sessions",
        1,
        PROCEDURE,
    ),
    (
        "nextgcore-amfd/src/ngap_path.rs",
        "release_all_pdu_sessions",
        1,
        PROCEDURE,
    ),
    (
        "nextgcore-amfd/src/ngap_path.rs",
        "release_ng_connections",
        1,
        PROCEDURE,
    ),
    (
        "nextgcore-amfd/src/ngap_path.rs",
        "send_registration_accept_reconciled",
        1,
        PROCEDURE,
    ),
    (
        "nextgcore-amfd/src/sbi_path.rs",
        "retry_peer_update",
        1,
        ONE_PEER,
    ),
    (
        "nextgcore-eesd/src/ecs_registration.rs",
        "refresh_once",
        1,
        ONE_PEER,
    ),
    (
        "nextgcore-eesd/src/ecs_registration.rs",
        "spawn_refresh",
        1,
        TIMER,
    ),
    (
        "nextgcore-eesd/src/main.rs",
        "spawn_lifecycle_sweep",
        1,
        TIMER,
    ),
    (
        "nextgcore-lmfd/src/amf_unsubscribe.rs",
        "spawn_reconciler",
        1,
        TIMER,
    ),
    (
        "nextgcore-lmfd/src/amf_unsubscribe.rs",
        "unsubscribe_all",
        1,
        CONCURRENT,
    ),
    (
        "nextgcore-mbsmfd/src/main.rs",
        "handle_mbs_session_release",
        1,
        PROCEDURE,
    ),
    (
        "nextgcore-mbsmfd/src/main.rs",
        "release_amf_contexts",
        1,
        PROCEDURE,
    ),
    (
        "nextgcore-mbsmfd/src/main.rs",
        "release_retries",
        1,
        PROCEDURE,
    ),
    (
        "nextgcore-mbsmfd/src/reconcile.rs",
        "spawn_reconciler",
        1,
        TIMER,
    ),
    (
        "nextgcore-nefd/src/southbound_reconcile.rs",
        "spawn_reconciler",
        1,
        TIMER,
    ),
    (
        "nextgcore-nwdafd/src/model_monitor.rs",
        "subscribe_at_anlf_retrying",
        1,
        ONE_PEER,
    ),
    (
        "nextgcore-pcfd/src/bsf_reconcile.rs",
        "reconcile_once",
        1,
        ONE_RESOLVED_PEER,
    ),
    (
        "nextgcore-pcfd/src/bsf_reconcile.rs",
        "spawn_reconciler",
        1,
        TIMER,
    ),
    (
        "nextgcore-smfd/src/main.rs",
        "await_release_in_flight_on",
        1,
        SHUTDOWN,
    ),
    (
        "nextgcore-smfd/src/main.rs",
        "drain_release_side_effects",
        1,
        SHUTDOWN,
    ),
    (
        "nextgcore-smfd/src/main.rs",
        "drain_s5s8_requests",
        1,
        SHUTDOWN,
    ),
    (
        "nextgcore-smfd/src/main.rs",
        "drain_sm_policy_deletes",
        1,
        SHUTDOWN,
    ),
    (
        "nextgcore-smfd/src/main.rs",
        "handle_sm_context_release",
        1,
        PROCEDURE,
    ),
    (
        "nextgcore-smfd/src/main.rs",
        "nsac_count_out_unreleased",
        1,
        SHUTDOWN,
    ),
    (
        "nextgcore-smfd/src/main.rs",
        "nsac_release_permits",
        1,
        LOCAL,
    ),
    (
        "nextgcore-smfd/src/main.rs",
        "release_side_effect_permits",
        1,
        LOCAL,
    ),
    (
        "nextgcore-smfd/src/main.rs",
        "release_side_effects",
        1,
        PROCEDURE,
    ),
    (
        "nextgcore-smfd/src/main.rs",
        "release_udm_cleanup",
        1,
        PROCEDURE,
    ),
    (
        "nextgcore-smfd/src/main.rs",
        "retry_n1n2_after_paging_conflict",
        1,
        PROCEDURE,
    ),
    (
        "nextgcore-smfd/src/main.rs",
        "spawn_release_side_effects_with",
        1,
        PROCEDURE,
    ),
    (
        "nextgcore-smfd/src/main.rs",
        "udm_release_permits",
        1,
        LOCAL,
    ),
    (
        "nextgcore-smfd/src/pfcp_path.rs",
        "drain_restart_fanouts",
        1,
        SHUTDOWN,
    ),
    ("nextgcore-smfd/src/qos_mon.rs", "reconcile", 1, LOCAL),
    (
        "nextgcore-smfd/src/reconcile.rs",
        "spawn_reconciler",
        1,
        TIMER,
    ),
    (
        "nextgcore-smfd/src/restoration.rs",
        "reconcile_session_not_found",
        1,
        PROCEDURE,
    ),
    (
        "nextgcore-smfd/src/restoration.rs",
        "release_epc_pdn_connections_scoped",
        1,
        PROCEDURE,
    ),
    (
        "nextgcore-tsctsf/src/actuation.rs",
        "delete_with_retry",
        1,
        ONE_PEER,
    ),
    (
        "nextgcore-tsctsf/src/reconcile.rs",
        "reconcile_once",
        1,
        ONE_RESOLVED_PEER,
    ),
    (
        "nextgcore-tsctsf/src/reconcile.rs",
        "spawn_reconciler",
        1,
        TIMER,
    ),
    (
        "nextgcore-udmd/src/app.rs",
        "handle_ee_unsubscribe",
        1,
        PROCEDURE,
    ),
    (
        "nextgcore-udmd/src/app.rs",
        "spawn_ee_expiry_sweep",
        1,
        TIMER,
    ),
    ("nextgcore-udmd/src/ee_amf.rs", "reconcile", 1, PROCEDURE),
    (
        "nextgcore-udmd/src/ee_amf.rs",
        "spawn_unsubscribe_reconciler",
        1,
        TIMER,
    ),
    (
        "nextgcore-udmd/src/ee_amf.rs",
        "spawn_amf_leg_renewal",
        1,
        TIMER,
    ),
    ("nextgcore-udmd/src/sdm_udr.rs", "drain", 1, CONCURRENT),
    ("nextgcore-udmd/src/sdm_udr.rs", "refresh_legs", 1, ONE_PEER),
    (
        "nextgcore-udmd/src/sdm_udr.rs",
        "spawn_leg_refresh",
        1,
        TIMER,
    ),
];

/// The words that name a pass over peers.
const PASS_WORDS: &[&str] = &[
    "refresh",
    "renew",
    "release",
    "reconcile",
    "sweep",
    "unsubscribe",
    "drain",
    "expir",
    "retry",
    "owed",
    "purge",
    "reap",
    "cleanup",
    "lapse",
];

/// The `{...}` block starting at or after `from` in `s`.
fn block_at(s: &str, from: usize) -> &str {
    let Some(open) = s[from..].find('{').map(|i| from + i) else {
        return "";
    };
    let mut depth = 0usize;
    for (i, c) in s[open..].char_indices() {
        match c {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return &s[open..open + i + 1];
                }
            }
            _ => {}
        }
    }
    &s[open..]
}

/// The `(...)` span opening at `open` in `s`.
fn paren_span(s: &str, open: usize) -> &str {
    let mut depth = 0usize;
    for (i, c) in s[open..].char_indices() {
        match c {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return &s[open..open + i + 1];
                }
            }
            _ => {}
        }
    }
    &s[open..]
}

fn is_ident(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

/// Whether `s` has an `.await` (#2223: as a token, so a field such as
/// hssd's `req.awaiting_peer` is not one).
fn awaits(s: &str) -> bool {
    s.match_indices(".await")
        .any(|(at, m)| !s[at + m.len()..].chars().next().is_some_and(is_ident))
}

/// Whether `body` runs its pass on the shared sweep.
fn on_sweep(body: &str) -> bool {
    body.contains("sweep::sweep(") || body.contains("sweep::retry_parked(")
}

/// Whether `body` has a `for`, `while` or `loop` whose block awaits.
fn loop_awaits(body: &str) -> bool {
    // #2216 R41 F3: a stream or iterator combinator whose closure awaits is a
    // loop too (`stream::iter(peers).for_each(|p| async { ...await })`, serial;
    // `for_each_concurrent(limit, ...)`, a hand-rolled bound).
    for call in [".for_each(", "for_each_concurrent(", ".then(", ".fold("] {
        for (at, _) in body.match_indices(call) {
            if awaits(paren_span(body, at + call.len() - 1)) {
                return true;
            }
        }
    }
    for kw in ["for", "while", "loop"] {
        for (at, _) in body.match_indices(kw) {
            let before = body[..at].chars().next_back();
            let after = body[at + kw.len()..].chars().next();
            if before.is_some_and(is_ident) || after.is_some_and(is_ident) {
                continue;
            }
            if awaits(block_at(body, at + kw.len())) {
                return true;
            }
        }
    }
    false
}

/// The fns of `src` (production code: cut at `#[cfg(test)] mod tests`), each
/// with its body: from its `fn` to the next fn's.
fn fns_of(src: &str) -> Vec<(String, &str)> {
    let src = match src.find("\n#[cfg(test)]\nmod tests") {
        Some(cut) => &src[..cut],
        None => src,
    };
    let heads: Vec<(usize, String)> = src
        .match_indices("fn ")
        .filter(|(at, _)| *at == 0 || !src[..*at].ends_with(is_ident))
        .map(|(at, _)| {
            let rest = &src[at + 3..];
            let end = rest.find(|c: char| !is_ident(c)).unwrap_or(rest.len());
            (at, rest[..end].to_string())
        })
        .collect();
    heads
        .iter()
        .enumerate()
        .map(|(i, (at, name))| {
            let end = heads.get(i + 1).map_or(src.len(), |(n, _)| *n);
            (name.clone(), &src[*at..end])
        })
        .collect()
}

/// Whether `body` itself looks like a hand-rolled pass: it builds a semaphore
/// (`Semaphore::new` / `const_new`) or awaits inside a loop, and does not run
/// on [`sweep`].
fn rolls_by_hand(body: &str) -> bool {
    let semaphore = body.contains("Semaphore::new(") || body.contains("Semaphore::const_new(");
    (semaphore || loop_awaits(body)) && !on_sweep(body)
}

fn is_pass_name(name: &str) -> bool {
    PASS_WORDS.iter().any(|w| name.contains(w))
}

/// The fns of `src` that look like a hand-rolled pass over peers: named for
/// one ([`PASS_WORDS`]) and [`rolls_by_hand`].
fn hand_rolled(src: &str) -> Vec<String> {
    fns_of(src)
        .into_iter()
        .filter(|(name, body)| is_pass_name(name) && rolls_by_hand(body))
        .map(|(name, _)| name)
        .collect()
}

/// R44's three planted shapes are flagged: the #2155 serial `for ... .await`,
/// a `drain_*` fn with a semaphore, and `Semaphore::const_new`; and R41's
/// (#2216): a serial `purge_*` loop (F2), and a stream `for_each` /
/// `for_each_concurrent(1, ...)` whose closure awaits (F3). A pass on the
/// shared sweep (or on `retry_parked`), a fn not named for a pass, and (#2223)
/// a loop that only reads a field named `awaiting_*` (hssd's
/// `sweep_pending_requests`, which awaits nothing), are not.
///
/// #2223 REVERT-VERIFIED: with `.await` matched as a substring,
/// `sweep_pending_requests` is flagged; without `retry_parked` in `on_sweep`,
/// `reconcile_on_retry_parked` is.
///
/// REVERT-VERIFIED: with the loop check dropped, the serial shape passes; with
/// only `Semaphore::new(` matched, `const_new` passes; with the old six words,
/// `drain_owed_deletes` passes.
#[test]
fn the_guard_flags_the_serial_and_bounded_shapes() {
    let src = r#"
async fn release_expired_legs(subs: Vec<Sub>) {
    for sub in &subs {
        release(sub).await;
    }
}
async fn drain_owed_deletes() {
    let gate = tokio::sync::Semaphore::new(8);
    let _ = gate;
}
static GATE: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(4);
async fn renew_all_legs() {
    let _ = &GATE;
    let g = tokio::sync::Semaphore::const_new(4);
    let _ = g;
}
async fn refresh_on_the_sweep(items: Vec<(String, u32)>) {
    for _ in 0..1 {}
    nextgcore_sbi::sweep::sweep(limits(), items, || (), |_, _, _| async { todo!() }).await;
}
async fn purge_stale_subscriptions(subs: Vec<Sub>) {
    for s in subs {
        delete(s).await;
    }
}
async fn refresh_all_peers(xs: Vec<Peer>) {
    futures::stream::iter(xs).for_each(|x| async move { refresh(x).await; }).await;
}
async fn cleanup_legs(xs: Vec<Peer>) {
    futures::stream::iter(xs).for_each_concurrent(1, |x| async move { release(x).await; }).await;
}
fn sweep_pending_requests(reqs: Vec<Req>) {
    for r in reqs {
        if r.awaiting_peer || r.awaited {
            send(r);
        }
    }
}
async fn reconcile_on_retry_parked(batch: Vec<(String, u32)>) {
    for b in &batch {
        log(b).await;
    }
    nextgcore_sbi::sweep::retry_parked(&B, limits(), batch, |_, i| async move { (None, i, ()) })
        .await;
}
async fn serve_requests(reqs: Vec<Req>) {
    for r in reqs {
        answer(r).await;
    }
}
"#;
    assert_eq!(
        hand_rolled(src),
        vec![
            "release_expired_legs",
            "drain_owed_deletes",
            "renew_all_legs",
            "purge_stale_subscriptions",
            "refresh_all_peers",
            "cleanup_legs",
        ]
    );
}

/// **#2186, source guard.** No production fn named for a pass over peers in any
/// `bins/*` crate runs it by hand (see [`hand_rolled`]): such a pass uses
/// [`sweep`]. A fn that is flagged and is not a peer sweep, or is one still to
/// move, is in [`ALLOWED`] with its reason; an entry that no longer matches
/// fails too, so the list cannot rot.
#[test]
fn no_hand_rolled_sweeps_remain() {
    let bins = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../bins");
    let mut found = Vec::new();
    let mut stack = vec![bins.clone()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).expect("bins/ is readable") {
            let path = entry.unwrap().path();
            if path.is_dir() {
                if path
                    .file_name()
                    .is_some_and(|n| n != "tests" && n != "target")
                {
                    stack.push(path);
                }
                continue;
            }
            let name = path.file_name().unwrap().to_string_lossy().to_string();
            if !name.ends_with(".rs") || name.ends_with("_tests.rs") || name == "tests.rs" {
                continue;
            }
            let rel = path
                .strip_prefix(&bins)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            let src = std::fs::read_to_string(&path).unwrap();
            for f in hand_rolled(&src) {
                found.push((rel.clone(), f));
            }
        }
    }
    let problems = allowlist_violations(&found, ALLOWED);
    assert!(
        problems.is_empty(),
        "hand-rolled passes over peers: use nextgcore_sbi::sweep::sweep (#2186), or list \
         one that is not a peer sweep in ALLOWED with its count and reason: {problems:?}"
    );
}

/// How `found` (file, fn name; one per flagged fn) differs from `allowed`: a
/// flagged fn with no entry, an entry whose count is not the number found (a
/// second same-named fn, or one gone), and an entry that matches nothing.
fn allowlist_violations(
    found: &[(String, String)],
    allowed: &[(&str, &str, usize, &str)],
) -> Vec<String> {
    let mut counts: std::collections::BTreeMap<(&str, &str), usize> = Default::default();
    for (f, n) in found {
        *counts.entry((f.as_str(), n.as_str())).or_default() += 1;
    }
    let mut out = Vec::new();
    for ((f, n), c) in &counts {
        match allowed.iter().find(|(af, an, _, _)| af == f && an == n) {
            None => out.push(format!("{f}: fn {n} (x{c}) is not in ALLOWED")),
            Some((_, _, want, _)) if want != c => {
                out.push(format!("{f}: fn {n}: {c} flagged, ALLOWED says {want}"))
            }
            Some(_) => {}
        }
    }
    for (f, n, _, _) in allowed {
        if !counts.contains_key(&(*f, *n)) {
            out.push(format!("{f}: fn {n} is in ALLOWED but matches nothing"));
        }
    }
    out
}

/// #2216 R41 F1: a second serial `reconcile_once` in a file whose one
/// `reconcile_once` is allowed is caught, because the entry carries its count.
///
/// REVERT-VERIFIED: with the count ignored (any number allowed), no violation.
#[test]
fn a_second_fn_of_an_allowed_name_in_the_same_file_is_caught() {
    let src = r#"
pub async fn reconcile_once() {
    for p in parked() {
        send(p).await;
    }
}
mod r41_extra {
    pub async fn reconcile_once(xs: Vec<u8>) {
        for x in xs {
            send(x).await;
        }
    }
}
"#;
    let found: Vec<(String, String)> = hand_rolled(src)
        .into_iter()
        .map(|n| ("nextgcore-amfd/src/nsac.rs".to_string(), n))
        .collect();
    assert_eq!(found.len(), 2);
    let allowed = [("nextgcore-amfd/src/nsac.rs", "reconcile_once", 1, PROCEDURE)];
    let v = allowlist_violations(&found, &allowed);
    assert_eq!(v.len(), 1, "{v:?}");
    assert!(v[0].contains("2 flagged, ALLOWED says 1"), "{v:?}");
    let allowed = [("nextgcore-amfd/src/nsac.rs", "reconcile_once", 2, PROCEDURE)];
    assert!(allowlist_violations(&found, &allowed).is_empty());
}
