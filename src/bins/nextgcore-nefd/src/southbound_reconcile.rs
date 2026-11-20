//! #1877: the reconciler for southbound unsubscribes that failed.
//!
//! A monitoring subscription the AF deletes (or one a create had to roll back)
//! owes its producer, the AMF or the UDM, a DELETE of the EE subscription the NEF
//! made there (TS 29.518 §5.3.2.3, TS 29.503 §5.5.2.3). That DELETE was tried once
//! and then only logged, while the local record was removed anyway, so a producer
//! that was down for a moment kept notifying the NEF for a subscription nobody
//! holds. Now a DELETE that fails is parked here and retried every
//! [`RECONCILE_PERIOD`] until the producer answers 2xx or 404 (it does not hold the
//! subscription). Same shape as #1817's and smfd #1875's reconcilers.
//!
//! Bounded at [`MAX_PENDING`]: parking one more evicts the oldest, logged at error
//! and counted `abandoned`. A pass sends for at most [`MAX_PASS`].
//!
//! #2086 (R30): durable with the NEF's state file. The set is written in the same
//! snapshot as the subscriptions (`parkedUnsubscribes`), and an unsubscribe is
//! owed ([`owe`]) BEFORE the removal of its subscription is persisted and before
//! its DELETE is sent, so no restart can find the subscription gone and the
//! unsubscribe it owes forgotten. A delivered one leaves the set ([`settle`]).

use crate::context::{SouthboundProducer, SouthboundRef};
use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::Duration;

/// Records parked before the oldest is abandoned.
pub const MAX_PENDING: usize = 4096;

/// How often a parked unsubscribe is retried.
#[cfg(not(test))]
pub const RECONCILE_PERIOD: Duration = Duration::from_secs(30);
#[cfg(test)]
pub const RECONCILE_PERIOD: Duration = Duration::from_millis(20);

/// The longest one pass sends for.
#[cfg(not(test))]
pub const MAX_PASS: Duration = Duration::from_secs(30);
#[cfg(test)]
pub const MAX_PASS: Duration = Duration::from_secs(2);

/// `nef_southbound_unsubscribes_reconciled_total{result}`: parked unsubscribes the
/// reconciler ended: `delivered` (2xx or 404), `abandoned` (evicted at the bound) or
/// `expired` (parked longer than [`MAX_AGE`]).
pub static RECONCILED: nextgcore_metrics::nf::CounterFamily =
    nextgcore_metrics::nf::CounterFamily::new(
        "nef_southbound_unsubscribes_reconciled_total",
        "Southbound (AMF/UDM) EE unsubscribes that failed and were parked, by how the \
         reconciler ended them",
        &["result"],
    );

/// `nef_southbound_unsubscribes_parked_total`: unsubscribes that failed and were parked.
pub static PARKED: nextgcore_metrics::nf::CounterFamily = nextgcore_metrics::nf::CounterFamily::new(
    "nef_southbound_unsubscribes_parked_total",
    "Southbound (AMF/UDM) EE unsubscribes that failed and were parked for the reconciler",
    &["producer"],
);

/// The parked unsubscribes, oldest first.
///
/// Every test that can write it (any that reaches a failing southbound unsubscribe,
/// through a handler or directly) holds `crate::context::NEF_CONTEXT_TEST_LOCK`,
/// the lock beside the NEF's process-global state, which this set is part of
/// (R27 #1947: a sibling test's park landed in another test's count, 1 run in 3).
fn pending() -> &'static Mutex<VecDeque<Parked>> {
    static PENDING: Mutex<VecDeque<Parked>> = Mutex::new(VecDeque::new());
    &PENDING
}

/// How long an unsubscribe stays parked before it is given up (`expired`): a
/// producer that has not answered for a day is gone, not restarting.
pub const MAX_AGE: Duration = Duration::from_secs(24 * 3600);

/// R27 #1972: the first wait before a producer whose DELETE failed is tried again,
/// doubled after each further failure up to [`BACKOFF_MAX`], and cleared by a
/// delivery. So a dead producer costs one request timeout per backoff period, not
/// one per pass.
#[cfg(not(test))]
pub const BACKOFF_BASE: Duration = Duration::from_secs(30);
#[cfg(test)]
pub const BACKOFF_BASE: Duration = Duration::from_millis(300);
/// The longest a failing producer is left alone between attempts.
pub const BACKOFF_MAX: Duration = Duration::from_secs(600);

/// Per producer (target base URI): its backoff (#1994: the shared one). Guarded
/// like [`pending`].
static BACKOFF: nextgcore_core::backoff::PeerBackoff =
    nextgcore_core::backoff::PeerBackoff::new(BACKOFF_BASE, BACKOFF_MAX);

/// The producer a parked unsubscribe is retried at: the one its subscription was
/// made at, else the producer URI configured now. Its backoff key.
fn target_of(southbound: &SouthboundRef) -> Option<String> {
    southbound
        .producer_base
        .clone()
        .or_else(|| crate::producer_uri(southbound.producer))
}

/// One parked unsubscribe, and when it was first parked.
#[derive(Debug, Clone)]
struct Parked {
    southbound: SouthboundRef,
    since: std::time::Instant,
}

fn lock() -> std::sync::MutexGuard<'static, VecDeque<Parked>> {
    pending().lock().unwrap_or_else(|e| e.into_inner())
}

fn evict(set: &mut VecDeque<Parked>) {
    for Parked {
        southbound: old, ..
    } in nextgcore_core::backoff::evict_oldest(set, MAX_PENDING, |p| p.since)
    {
        log::error!(
            "{} unsubscribe of {} abandoned: {MAX_PENDING} are already pending",
            old.producer.as_str(),
            old.subscription_id
        );
        RECONCILED.inc(&["abandoned"]);
    }
}

/// #2086: record that `southbound` is owed a DELETE, before anything that
/// depends on it is persisted or sent. Silent (it is not a failure yet), and not
/// persisted here: the caller's next persist writes it (with the removal it goes
/// with). Returns whether it was added.
pub fn owe(southbound: SouthboundRef) -> bool {
    let mut set = lock();
    if set.iter().any(|p| p.southbound == southbound) {
        return false;
    }
    set.push_back(Parked {
        southbound,
        since: std::time::Instant::now(),
    });
    evict(&mut set);
    true
}

/// #2148: whether a DELETE of `southbound` is still owed (not yet delivered).
pub fn is_owed(southbound: &SouthboundRef) -> bool {
    lock().iter().any(|p| p.southbound == *southbound)
}

/// #2086: `southbound`'s DELETE was delivered: it is no longer owed. Persisted.
pub fn settle(southbound: &SouthboundRef) {
    let removed = {
        let mut set = lock();
        let before = set.len();
        set.retain(|p| p.southbound != *southbound);
        set.len() != before
    };
    if removed {
        persist_state();
    }
}

/// #2086: the owed unsubscribes, oldest first, for the state snapshot.
pub fn snapshot() -> Vec<SouthboundRef> {
    lock().iter().map(|p| p.southbound.clone()).collect()
}

/// #2086: install the owed unsubscribes a state snapshot held (startup). Their
/// [`MAX_AGE`] counts from now: the time parked before the restart is not known.
pub fn restore(refs: Vec<SouthboundRef>) {
    for southbound in refs {
        owe(southbound);
    }
}

/// #2086: write the NEF state (subscriptions and owed unsubscribes) now.
fn persist_state() {
    if let Ok(c) = crate::context::nef_self().read() {
        c.persist_now();
    }
}

/// Park an unsubscribe that failed. One already parked is not parked twice.
pub fn park(southbound: SouthboundRef) {
    let mut set = lock();
    if set.iter().any(|p| p.southbound == southbound) {
        // #2086: already owed (its DELETE was tried after `owe`): now it failed.
        drop(set);
        log::warn!(
            "{} unsubscribe of {} failed; parked, retried every {RECONCILE_PERIOD:?}",
            southbound.producer.as_str(),
            southbound.subscription_id
        );
        PARKED.inc(&[match southbound.producer {
            SouthboundProducer::Amf => "amf",
            SouthboundProducer::Udm => "udm",
        }]);
        return;
    }
    log::warn!(
        "{} unsubscribe of {} failed; parked, retried every {RECONCILE_PERIOD:?}",
        southbound.producer.as_str(),
        southbound.subscription_id
    );
    PARKED.inc(&[match southbound.producer {
        SouthboundProducer::Amf => "amf",
        SouthboundProducer::Udm => "udm",
    }]);
    set.push_back(Parked {
        southbound,
        since: std::time::Instant::now(),
    });
    evict(&mut set);
    drop(set);
    persist_state();
}

/// How many unsubscribes are parked.
pub fn pending_count() -> usize {
    lock().len()
}

/// The parked unsubscribes (tests).
#[cfg(test)]
pub fn parked() -> Vec<SouthboundRef> {
    lock().iter().map(|p| p.southbound.clone()).collect()
}

/// The backoff a producer is in (tests).
#[cfg(test)]
pub fn backoff_of(target: &str) -> Option<Duration> {
    BACKOFF.current(target)
}

/// Record a failure at a producer (tests).
#[cfg(test)]
pub fn note_failure_for_test(target: &str) {
    BACKOFF.note_failure(target);
}

/// Forget every parked unsubscribe (a test's own).
#[cfg(test)]
pub fn clear_for_test() {
    lock().clear();
    BACKOFF.clear();
}

/// One pass: retry the parked unsubscribes in turn order, for at most
/// [`MAX_PASS`], at the producer each subscription was made at (else the producer
/// URI configured now, for one recorded before that was kept). Returns how many
/// ended.
///
/// No producer can starve the others (R30 #1954, R27 #1972): once a DELETE to a
/// producer fails it backs off ([`BACKOFF_BASE`], doubling to [`BACKOFF_MAX`]), so
/// its other unsubscribes wait, in this pass and the next ones, instead of each
/// costing a timeout; and a tried one goes to the BACK of the queue while one this
/// pass did not reach keeps its place at the front. One parked longer than
/// [`MAX_AGE`] is given up as `expired`.
pub async fn reconcile_once() -> usize {
    let batch: Vec<Parked> = lock().drain(..).collect();
    let deadline = tokio::time::Instant::now() + MAX_PASS;
    let mut ended = 0;
    let mut untried = Vec::new();
    let mut failed = Vec::new();
    for parked in batch {
        let southbound = &parked.southbound;
        if parked.since.elapsed() > MAX_AGE {
            log::error!(
                "{} unsubscribe of {} expired after {MAX_AGE:?}",
                southbound.producer.as_str(),
                southbound.subscription_id
            );
            RECONCILED.inc(&["expired"]);
            ended += 1;
            continue;
        }
        let uri = target_of(southbound);
        let target = uri.clone().unwrap_or_default();
        // A producer that failed (in this pass or an earlier one) is backing off:
        // its unsubscribes wait, so it costs one attempt per backoff period.
        if tokio::time::Instant::now() >= deadline || BACKOFF.backing_off(&target) {
            untried.push(parked);
            continue;
        }
        if crate::try_southbound_unsubscribe(uri, southbound).await {
            BACKOFF.note_success(&target);
            log::info!(
                "{} unsubscribe of {}: reconciled",
                southbound.producer.as_str(),
                southbound.subscription_id
            );
            RECONCILED.inc(&["delivered"]);
            ended += 1;
        } else {
            BACKOFF.note_failure(&target);
            failed.push(parked);
        }
    }
    let mut set = lock();
    for parked in untried.into_iter().rev() {
        if !set.iter().any(|p| p.southbound == parked.southbound) {
            set.push_front(parked);
        }
    }
    for parked in failed {
        if !set.iter().any(|p| p.southbound == parked.southbound) {
            set.push_back(parked);
        }
    }
    evict(&mut set);
    let parked: Vec<SouthboundRef> = set.iter().map(|p| p.southbound.clone()).collect();
    drop(set);
    prune_backoff(&parked);
    // #2086: the ones that ended leave the state file too.
    if ended > 0 {
        persist_state();
    }
    ended
}

/// #1994: forget the backoff of a producer with nothing left parked, so one that
/// never comes back does not stay in the map for good.
fn prune_backoff(parked: &[SouthboundRef]) {
    let live: std::collections::HashSet<String> = parked
        .iter()
        .map(|s| target_of(s).unwrap_or_default())
        .collect();
    BACKOFF.retain(|target| live.contains(target));
}

/// Run [`reconcile_once`] every [`RECONCILE_PERIOD`] for the life of the process.
pub fn spawn_reconciler() -> tokio::task::JoinHandle<()> {
    tokio::spawn(async {
        let mut timer = tokio::time::interval(RECONCILE_PERIOD);
        timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        timer.tick().await;
        loop {
            timer.tick().await;
            reconcile_once().await;
        }
    })
}

/// The reconciler's families, for `/metrics`.
pub fn render(out: &mut String) {
    use std::fmt::Write as _;
    nextgcore_metrics::nf::write_header(
        out,
        "nef_southbound_unsubscribes_pending",
        "gauge",
        "Southbound (AMF/UDM) EE unsubscribes parked for the reconciler",
    );
    let _ = writeln!(
        out,
        "nef_southbound_unsubscribes_pending {}",
        pending_count()
    );
    PARKED.render(out);
    RECONCILED.render(out);
}
