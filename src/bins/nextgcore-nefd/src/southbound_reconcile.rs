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
//! and counted `abandoned`. A pass sends for at most [`MAX_PASS`]. Memory-only, like
//! the NEF's subscriptions themselves: a restart forgets both.

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
/// reconciler ended: `delivered` (2xx or 404) or `abandoned` (evicted at the bound).
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
/// Tests that read or write it hold [`PENDING_TEST_LOCK`], declared beside it.
fn pending() -> &'static Mutex<VecDeque<SouthboundRef>> {
    static PENDING: Mutex<VecDeque<SouthboundRef>> = Mutex::new(VecDeque::new());
    &PENDING
}

/// Serialises the tests that touch [`pending`]: one test's reconcile pass would
/// otherwise deliver or drain another's parked unsubscribe.
#[cfg(test)]
pub static PENDING_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn lock() -> std::sync::MutexGuard<'static, VecDeque<SouthboundRef>> {
    pending().lock().unwrap_or_else(|e| e.into_inner())
}

fn evict(set: &mut VecDeque<SouthboundRef>) {
    while set.len() > MAX_PENDING {
        if let Some(old) = set.pop_front() {
            log::error!(
                "{} unsubscribe of {} abandoned: {MAX_PENDING} are already pending",
                old.producer.as_str(),
                old.subscription_id
            );
            RECONCILED.inc(&["abandoned"]);
        }
    }
}

/// Park an unsubscribe that failed. One already parked is not parked twice.
pub fn park(southbound: SouthboundRef) {
    let mut set = lock();
    if set.contains(&southbound) {
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
    set.push_back(southbound);
    evict(&mut set);
}

/// How many unsubscribes are parked.
pub fn pending_count() -> usize {
    lock().len()
}

/// The parked unsubscribes (tests).
#[cfg(test)]
pub fn parked() -> Vec<SouthboundRef> {
    lock().iter().cloned().collect()
}

/// Forget every parked unsubscribe (a test's own).
#[cfg(test)]
pub fn clear_for_test() {
    lock().clear();
}

/// One pass: retry the parked unsubscribes, oldest first, for at most
/// [`MAX_PASS`], against the producer URI configured now. Returns how many ended.
pub async fn reconcile_once() -> usize {
    let batch: Vec<SouthboundRef> = lock().drain(..).collect();
    let deadline = tokio::time::Instant::now() + MAX_PASS;
    let mut ended = 0;
    let mut still = Vec::new();
    for southbound in batch {
        if tokio::time::Instant::now() >= deadline {
            still.push(southbound);
            continue;
        }
        let uri = crate::producer_uri(southbound.producer);
        if crate::try_southbound_unsubscribe(uri, &southbound).await {
            log::info!(
                "{} unsubscribe of {}: reconciled",
                southbound.producer.as_str(),
                southbound.subscription_id
            );
            RECONCILED.inc(&["delivered"]);
            ended += 1;
        } else {
            still.push(southbound);
        }
    }
    let mut set = lock();
    for southbound in still.into_iter().rev() {
        if !set.contains(&southbound) {
            set.push_front(southbound);
        }
    }
    evict(&mut set);
    ended
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
