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

/// The functions that hand-rolled a bounded sweep before #2186 and still hold a
/// semaphore for a reason that is not a peer sweep, each with that reason.
const NOT_SWEEPS: &[(&str, &str, &str)] = &[
    (
        "nextgcore-smfd/src/main.rs",
        "release_side_effect_permits",
        "a process-wide fan-out bound for session release side effects, not a pass",
    ),
    (
        "nextgcore-smfd/src/main.rs",
        "udm_release_permits",
        "a process-wide fan-out bound, not a pass",
    ),
    (
        "nextgcore-smfd/src/main.rs",
        "nsac_release_permits",
        "a process-wide fan-out bound, not a pass",
    ),
    (
        "nextgcore-smfd/src/main.rs",
        "nsac_count_out_unreleased",
        "a one-shot shutdown count-out bounded by the shutdown budget, not a periodic \
         pass; left for smfd's owner (#2186 PR)",
    ),
    (
        "nextgcore-udmd/src/sdm_udr.rs",
        "refresh_legs",
        "every leg is at the one UDR, so no peer can hold another back; its \
         `Refreshed::Failed` does not tell a dead UDR from a refused leg, which parking \
         needs (#2186 PR)",
    ),
];

/// **#2186, source guard.** No production fn named for a refresh, renew,
/// release, reconcile, sweep or unsubscribe pass in any `bins/*` crate builds
/// its own `Semaphore`: such a pass uses [`sweep`]. A new hand-rolled one fails
/// here; a semaphore that is not a peer sweep goes in [`NOT_SWEEPS`] with its
/// reason.
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
            let src = std::fs::read_to_string(&path).unwrap();
            let src = match src.find("\n#[cfg(test)]\nmod tests") {
                Some(cut) => &src[..cut],
                None => &src[..],
            };
            let rel = path
                .strip_prefix(&bins)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            let heads: Vec<(usize, String)> = src
                .match_indices("fn ")
                .filter(|(at, _)| *at == 0 || src[..*at].ends_with([' ', '\n']))
                .map(|(at, _)| {
                    let rest = &src[at + 3..];
                    let end = rest
                        .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                        .unwrap_or(rest.len());
                    (at, rest[..end].to_string())
                })
                .collect();
            for (i, (at, fname)) in heads.iter().enumerate() {
                let end = heads.get(i + 1).map_or(src.len(), |(n, _)| *n);
                let body = &src[*at..end];
                let named = [
                    "refresh",
                    "renew",
                    "release",
                    "reconcile",
                    "sweep",
                    "unsubscribe",
                ]
                .iter()
                .any(|w| fname.contains(w));
                if named
                    && body.contains("Semaphore::new(")
                    && !NOT_SWEEPS
                        .iter()
                        .any(|(f, n, _)| *f == rel && *n == fname.as_str())
                {
                    found.push(format!("{rel}: fn {fname}"));
                }
            }
        }
    }
    assert!(
        found.is_empty(),
        "hand-rolled sweeps: use nextgcore_sbi::sweep::sweep (#2186): {found:?}"
    );
}
