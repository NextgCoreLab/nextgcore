//! Per-peer retry backoff and oldest-first eviction for the parked-cleanup
//! reconcilers (#1994).
//!
//! nefd, smfd, amfd, mbsmfd and tsctsf each park SBI cleanups that failed and
//! retry them on a timer. They used to carry five copies of the same backoff map.
//! R31/R32 found the same gaps in all five copies:
//! - nothing pinned the cap;
//! - the map was never pruned;
//! - nothing checked that a success clears the backoff;
//! - four of them evicted the FRONT of a rotating queue, which is not the oldest
//!   entry.
//!
//! This module is the one implementation they share.

use std::collections::{BTreeMap, VecDeque};
use std::sync::{Mutex, MutexGuard};
use std::time::Duration;
use tokio::time::Instant;

/// When a peer may next be tried, and the backoff that set it.
type Entries = BTreeMap<String, (Instant, Duration)>;

/// Per-peer backoff: `base` after a peer's first failure, doubled after each
/// further one up to `max`, and cleared by a success. A peer that is backing off
/// is skipped, so a dead peer costs one request timeout per backoff period, not
/// one per pass.
///
/// `const`-constructible, so a reconciler declares it as a `static` beside the
/// parked set it belongs to; tests that touch it hold that set's lock.
#[derive(Debug)]
pub struct PeerBackoff {
    base: Duration,
    max: Duration,
    /// What "now" is: [`Instant::now`], or a test's own clock ([`Self::with_clock`]).
    now: fn() -> Instant,
    peers: Mutex<Entries>,
}

impl PeerBackoff {
    /// A backoff starting at `base` and capped at `max`.
    pub const fn new(base: Duration, max: Duration) -> Self {
        Self::with_clock(base, max, Instant::now)
    }

    /// [`Self::new`], reading the time from `now` (#2196). A test whose runtime
    /// cannot be paused (real sockets on a multi-thread runtime) passes a clock it
    /// advances itself, so "inside the window" does not depend on how loaded the
    /// host is; production passes [`Instant::now`] through [`Self::new`].
    pub const fn with_clock(base: Duration, max: Duration, now: fn() -> Instant) -> Self {
        Self {
            base,
            max,
            now,
            peers: Mutex::new(BTreeMap::new()),
        }
    }

    fn peers(&self) -> MutexGuard<'_, Entries> {
        self.peers.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Whether `peer` failed recently enough that it is not to be tried yet.
    pub fn backing_off(&self, peer: &str) -> bool {
        self.peers()
            .get(peer)
            .is_some_and(|(next, _)| (self.now)() < *next)
    }

    /// Record a failure at `peer`: it is left alone for `base` after its first
    /// failure, doubled after each further one, up to `max`. Returns that wait.
    pub fn note_failure(&self, peer: &str) -> Duration {
        let mut peers = self.peers();
        let wait = peers
            .get(peer)
            .map_or(self.base, |(_, current)| current.saturating_mul(2))
            .min(self.max);
        peers.insert(peer.to_string(), ((self.now)() + wait, wait));
        wait
    }

    /// Record a success at `peer`: its backoff is cleared.
    pub fn note_success(&self, peer: &str) {
        self.peers().remove(peer);
    }

    /// The backoff `peer` is in, if any.
    pub fn current(&self, peer: &str) -> Option<Duration> {
        self.peers().get(peer).map(|(_, wait)| *wait)
    }

    /// Keep only the peers `keep` says still have something parked, so a peer
    /// that never comes back does not stay in the map for good.
    pub fn retain(&self, mut keep: impl FnMut(&str) -> bool) {
        self.peers().retain(|peer, _| keep(peer));
    }

    /// How many peers are tracked.
    pub fn len(&self) -> usize {
        self.peers().len()
    }

    /// Whether no peer is tracked.
    pub fn is_empty(&self) -> bool {
        self.peers().is_empty()
    }

    /// Forget every peer.
    pub fn clear(&self) {
        self.peers().clear();
    }
}

/// Evict from `set` until at most `max` are left, the oldest by `since` first,
/// wherever rotation has put it. Returns the evicted ones, oldest first, for the
/// caller to log and count.
///
/// A reconciler's queue rotates (a failed entry goes to the back), so its front
/// is the next to be tried, not the oldest: popping the front evicted a young
/// entry and kept an old one.
pub fn evict_oldest<T, K: Ord>(
    set: &mut VecDeque<T>,
    max: usize,
    since: impl Fn(&T) -> K,
) -> Vec<T> {
    let mut evicted = Vec::new();
    while set.len() > max {
        let Some(oldest) = set
            .iter()
            .enumerate()
            .min_by_key(|(_, item)| since(item))
            .map(|(i, _)| i)
        else {
            break;
        };
        evicted.extend(set.remove(oldest));
    }
    evicted
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: Duration = Duration::from_secs(30);
    const MAX: Duration = Duration::from_secs(600);

    /// The wait doubles from `base` and stops at `max`.
    ///
    /// REVERT-VERIFIED: with the `.min(self.max)` removed, this fails: the wait
    /// passes 600 s.
    #[test]
    fn the_backoff_doubles_up_to_its_cap_1994() {
        let b = PeerBackoff::new(BASE, MAX);
        assert_eq!(b.note_failure("p"), BASE);
        assert_eq!(b.note_failure("p"), BASE * 2);
        assert_eq!(b.note_failure("p"), BASE * 4);
        for _ in 0..40 {
            b.note_failure("p");
        }
        assert_eq!(b.current("p"), Some(MAX));
        // A base above the cap is capped too.
        let tight = PeerBackoff::new(MAX * 2, MAX);
        assert_eq!(tight.note_failure("p"), MAX);
    }

    /// A success clears the peer's backoff: it is tried at once, and its next
    /// failure starts from `base` again.
    ///
    /// REVERT-VERIFIED: with `note_success` a no-op, this fails: the peer is
    /// still backing off.
    #[tokio::test(start_paused = true)]
    async fn a_success_clears_the_backoff_1994() {
        let b = PeerBackoff::new(BASE, MAX);
        b.note_failure("p");
        b.note_failure("p");
        assert!(b.backing_off("p"));
        b.note_success("p");
        assert!(!b.backing_off("p"), "tried at once after a success");
        assert_eq!(b.current("p"), None);
        assert_eq!(b.note_failure("p"), BASE, "starts over");
    }

    /// A peer is skipped for exactly its wait, and only that peer.
    #[tokio::test(start_paused = true)]
    async fn a_failed_peer_is_skipped_for_its_wait_only_1994() {
        let b = PeerBackoff::new(BASE, MAX);
        b.note_failure("dead");
        assert!(b.backing_off("dead"));
        assert!(!b.backing_off("healthy"));
        tokio::time::advance(BASE - Duration::from_millis(1)).await;
        assert!(b.backing_off("dead"));
        tokio::time::advance(Duration::from_millis(1)).await;
        assert!(!b.backing_off("dead"), "due again after its wait");
    }

    /// #2196: a backoff built `with_clock` reads that clock, not the runtime's:
    /// the window opens and closes only as that clock moves.
    ///
    /// REVERT-VERIFIED: with `backing_off` and `note_failure` reading
    /// `Instant::now()` again, this fails: the peer is still backing off after
    /// its clock has passed the wait.
    #[test]
    fn a_backoff_reads_its_own_clock_2196() {
        use std::sync::atomic::{AtomicU64, Ordering};
        use std::sync::OnceLock;
        static EPOCH: OnceLock<Instant> = OnceLock::new();
        static OFFSET_MS: AtomicU64 = AtomicU64::new(0);
        fn now() -> Instant {
            *EPOCH.get_or_init(Instant::now)
                + Duration::from_millis(OFFSET_MS.load(Ordering::SeqCst))
        }
        let b = PeerBackoff::with_clock(BASE, MAX, now);
        b.note_failure("dead");
        OFFSET_MS.store(
            (BASE - Duration::from_millis(1)).as_millis() as u64,
            Ordering::SeqCst,
        );
        assert!(b.backing_off("dead"), "inside its wait on its clock");
        OFFSET_MS.store(BASE.as_millis() as u64, Ordering::SeqCst);
        assert!(!b.backing_off("dead"), "due once its clock passes the wait");
    }

    /// `retain` drops the peers with nothing left parked.
    ///
    /// REVERT-VERIFIED: with `retain` a no-op, this fails: "gone" is kept.
    #[test]
    fn retain_prunes_the_peers_not_kept_1994() {
        let b = PeerBackoff::new(BASE, MAX);
        b.note_failure("gone");
        b.note_failure("kept");
        b.retain(|peer| peer == "kept");
        assert_eq!(b.current("gone"), None);
        assert_eq!(b.current("kept"), Some(BASE));
        assert_eq!(b.len(), 1);
    }

    /// Eviction takes the oldest wherever it is in the queue, not the front.
    ///
    /// REVERT-VERIFIED: with `evict_oldest` popping the front, this fails: the
    /// young front entry is evicted.
    #[test]
    fn eviction_takes_the_oldest_not_the_front_1994() {
        // (name, since): rotation has moved the oldest to the back.
        let mut set: VecDeque<(&str, u32)> = [("young", 5), ("mid", 3), ("oldest", 1)]
            .into_iter()
            .collect();
        let evicted = evict_oldest(&mut set, 2, |(_, since)| *since);
        assert_eq!(evicted, vec![("oldest", 1)]);
        assert_eq!(set, VecDeque::from([("young", 5), ("mid", 3)]));
        let evicted = evict_oldest(&mut set, 0, |(_, since)| *since);
        assert_eq!(evicted, vec![("mid", 3), ("young", 5)], "oldest first");
        assert!(evict_oldest(&mut set, 0, |(_, since)| *since).is_empty());
    }
}
