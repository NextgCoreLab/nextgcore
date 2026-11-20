//! One bounded per-peer sweep for every periodic pass that calls remote peers
//! (#2186): refresh, renew, release and unsubscribe loops.
//!
//! The defect this replaces shipped three times (#2128 nefd refresh, #2155
//! udmd AMF release, #2182 udmd AMF renewal): a pass that calls peers one at a
//! time with a per-call timeout and no skip-on-failure, so one dead peer holds
//! healthy peers' items past their deadlines. [`sweep`] gives every such pass
//! the same shape:
//!
//! - items are grouped by peer; at most [`SweepLimits::per_peer`] of one peer's
//!   items are in flight at once, and at most [`SweepLimits::global`] across
//!   all peers;
//! - an item whose work answers [`Verdict::PeerDown`] parks its peer: that
//!   peer's items not yet started are skipped for the rest of the pass
//!   ([`Skip::PeerParked`]), so a blackholed peer costs at most `per_peer`
//!   request timeouts per pass;
//! - the pass has a time budget (measured on Tokio's clock) ([`SweepLimits::budget`]): an item not started
//!   when it runs out is skipped ([`Skip::Budget`]) and is the next pass's;
//! - the clock is read afresh for each item, just before its work starts, so
//!   a deadline judged by the work is judged against the time it is sent, not
//!   the time the pass began.
//!
//! The work runs on Tokio tasks owned by the sweep (a [`tokio::task::JoinSet`]
//! per peer and one for the peers), so dropping the sweep's future aborts
//! every item still in flight: nothing outlives a cancelled pass.
//!
//! New passes use this helper; `tests::no_hand_rolled_sweeps_remain` is the
//! source guard that fails on a new hand-rolled one in the migrated crates.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio::time::Instant;

/// The bounds of one pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SweepLimits {
    /// Items of one peer in flight at once (at least 1).
    pub per_peer: usize,
    /// Items in flight at once across all peers (at least 1).
    pub global: usize,
    /// How long the pass may start new items for.
    pub budget: Duration,
}

impl SweepLimits {
    fn normalised(self) -> Self {
        Self {
            per_peer: self.per_peer.max(1),
            global: self.global.max(1),
            budget: self.budget,
        }
    }
}

/// What one item's work says about its peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// The peer answered (whatever the answer): keep going.
    Answered,
    /// The peer did not answer, or failed as a peer (a timeout, a refused
    /// connection, a 5xx): park it for the rest of the pass.
    PeerDown,
}

/// Why an item was not started in this pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Skip {
    /// An earlier item of the same peer answered [`Verdict::PeerDown`].
    PeerParked,
    /// The pass's time budget ran out first.
    Budget,
}

/// What a pass did: every item is in exactly one of the two lists.
#[derive(Debug)]
pub struct SweepReport<K, I, R> {
    /// The items whose work ran, with its result, per peer in input order.
    pub done: Vec<(K, R)>,
    /// The items not started, with the reason, per peer in input order.
    pub skipped: Vec<(K, I, Skip)>,
}

impl<K, I, R> SweepReport<K, I, R> {
    /// How many items were skipped for `why`.
    pub fn skipped_for(&self, why: Skip) -> usize {
        self.skipped.iter().filter(|(_, _, s)| *s == why).count()
    }
}

/// Run `work` for every `(peer, item)` of `items` under `limits` (see the
/// module docs). `clock` is read once per item, just before its work starts,
/// and the value is handed to the work. Peers are visited in key order, and a
/// peer's items in the order given.
///
/// A panic in `work` is resumed here, after the pass's other tasks are aborted.
pub async fn sweep<K, I, R, N, C, F, Fut>(
    limits: SweepLimits,
    items: impl IntoIterator<Item = (K, I)>,
    clock: C,
    work: F,
) -> SweepReport<K, I, R>
where
    K: Ord + Clone + Send + 'static,
    I: Send + 'static,
    R: Send + 'static,
    N: Send + 'static,
    C: Fn() -> N + Send + Sync + 'static,
    F: Fn(K, I, N) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = (Verdict, R)> + Send + 'static,
{
    let limits = limits.normalised();
    let started = Instant::now();
    let mut by_peer: BTreeMap<K, Vec<I>> = BTreeMap::new();
    for (k, i) in items {
        by_peer.entry(k).or_default().push(i);
    }
    let global = Arc::new(Semaphore::new(limits.global));
    let clock = Arc::new(clock);
    let work = Arc::new(work);
    let mut peers = JoinSet::new();
    let n_peers = by_peer.len();
    for (idx, (k, list)) in by_peer.into_iter().enumerate() {
        let (global, clock, work) = (global.clone(), clock.clone(), work.clone());
        peers.spawn(async move {
            let r = peer_pass(k, list, limits, started, global, clock, work).await;
            (idx, r)
        });
    }
    let mut parts: Vec<Option<PeerPart<K, I, R>>> = (0..n_peers).map(|_| None).collect();
    while let Some(joined) = peers.join_next().await {
        match joined {
            Ok((idx, part)) => parts[idx] = Some(part),
            Err(e) if e.is_panic() => std::panic::resume_unwind(e.into_panic()),
            Err(e) => log::error!("a sweep peer task ended: {e}"),
        }
    }
    let mut report = SweepReport {
        done: Vec::new(),
        skipped: Vec::new(),
    };
    for part in parts.into_iter().flatten() {
        report
            .done
            .extend(part.done.into_iter().map(|(_, k, r)| (k, r)));
        report
            .skipped
            .extend(part.skipped.into_iter().map(|(_, k, i, s)| (k, i, s)));
    }
    report
}

struct PeerPart<K, I, R> {
    done: Vec<(usize, K, R)>,
    skipped: Vec<(usize, K, I, Skip)>,
}

async fn peer_pass<K, I, R, N, C, F, Fut>(
    peer: K,
    list: Vec<I>,
    limits: SweepLimits,
    started: Instant,
    global: Arc<Semaphore>,
    clock: Arc<C>,
    work: Arc<F>,
) -> PeerPart<K, I, R>
where
    K: Clone + Send + 'static,
    I: Send + 'static,
    R: Send + 'static,
    N: Send + 'static,
    C: Fn() -> N + Send + Sync + 'static,
    F: Fn(K, I, N) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = (Verdict, R)> + Send + 'static,
{
    let parked = Arc::new(AtomicBool::new(false));
    let mut part = PeerPart {
        done: Vec::new(),
        skipped: Vec::new(),
    };
    let mut queue = list.into_iter().enumerate();
    let mut inflight: JoinSet<(usize, Verdict, R)> = JoinSet::new();
    loop {
        while inflight.len() < limits.per_peer {
            let Some((n, item)) = queue.next() else {
                break;
            };
            if parked.load(Ordering::Acquire) {
                part.skipped.push((n, peer.clone(), item, Skip::PeerParked));
                continue;
            }
            if started.elapsed() >= limits.budget {
                part.skipped.push((n, peer.clone(), item, Skip::Budget));
                continue;
            }
            let Ok(permit) = global.clone().acquire_owned().await else {
                part.skipped.push((n, peer.clone(), item, Skip::Budget));
                continue;
            };
            // Waiting for a global slot may have used up the budget.
            if started.elapsed() >= limits.budget {
                part.skipped.push((n, peer.clone(), item, Skip::Budget));
                continue;
            }
            if parked.load(Ordering::Acquire) {
                part.skipped.push((n, peer.clone(), item, Skip::PeerParked));
                continue;
            }
            let now = clock();
            let fut = work(peer.clone(), item, now);
            let parked = parked.clone();
            inflight.spawn(async move {
                let (verdict, r) = fut.await;
                drop(permit);
                if verdict == Verdict::PeerDown {
                    parked.store(true, Ordering::Release);
                }
                (n, verdict, r)
            });
        }
        match inflight.join_next().await {
            None => break,
            Some(Ok((n, _, r))) => part.done.push((n, peer.clone(), r)),
            Some(Err(e)) if e.is_panic() => std::panic::resume_unwind(e.into_panic()),
            Some(Err(e)) => log::error!("a sweep item task ended: {e}"),
        }
    }
    part.done.sort_by_key(|(n, ..)| *n);
    part.skipped.sort_by_key(|(n, ..)| *n);
    part
}

#[cfg(test)]
#[path = "sweep_tests.rs"]
mod tests;
