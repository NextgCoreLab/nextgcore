//! #1817: the reconciler for `Npcf_PolicyAuthorization_Delete`s that outlived their
//! retry budget.
//!
//! [`crate::actuation`]'s Delete is tried once and then on its `DELETE_RETRY_DELAYS`
//! (about 31 s in all), keeping the resource's `appSessionId` throughout (#1754). A
//! PCF that was down for longer used to keep the app session for ever: the retry
//! task logged at error and stopped, and nothing ever asked again, so the PCF went
//! on enforcing the AF session's policy (TS 29.514 §4.2.4) for a configuration the
//! consumer had deleted. Now the resource is parked here and its Delete retried on
//! [`RECONCILE_PERIOD`] until the PCF answers 2xx or 404.
//!
//! Bounded: at most [`MAX_PENDING`] resources are parked. Parking one more evicts
//! the oldest, whose `appSessionId` is then forgotten; that is logged at error and
//! counted as `abandoned`, so a permanently unreachable PCF cannot grow the set (or
//! the `appSessionId` map) without limit.
//!
//! No pass is spent on a dead PCF (#1961, the #1954 / #1972 pattern): tsctsf sends
//! every Delete to the one PCF it resolves, so once a Delete fails that PCF backs
//! off ([`BACKOFF_BASE`], doubling to [`BACKOFF_MAX`]) and the rest wait, in this
//! pass and later ones, instead of each costing a timeout. A resource tried and
//! failed goes to the BACK of the queue; one not reached keeps its place at the
//! front. One parked longer than [`MAX_AGE`] ends as `expired`.
//!
//! Ceiling: the set is in memory, like the configurations it serves. tsctsf has no
//! durable store, so a restart forgets both; the PCF's own app-session lifetime is
//! what covers that case.
//!
//! Tests that read or write the set hold [`crate::context::PROCESS_STATE_TEST_LOCK`],
//! the crate's one ambient-state lock, which every actuation test already takes.

use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::Duration;

/// Resources parked before the oldest is abandoned.
pub const MAX_PENDING: usize = 4096;

/// How often a parked Delete is retried.
#[cfg(not(test))]
pub const RECONCILE_PERIOD: Duration = Duration::from_secs(30);
#[cfg(test)]
pub const RECONCILE_PERIOD: Duration = Duration::from_millis(20);

/// `nextgcore_tsctsf_pcf_app_session_delete_reconciled_total{result}`: parked
/// Deletes the reconciler delivered (`deleted`), evicted at the bound
/// (`abandoned`), or gave up after [`MAX_AGE`] (`expired`, #1961).
pub static RECONCILED: nextgcore_metrics::nf::CounterFamily =
    nextgcore_metrics::nf::CounterFamily::new(
        "nextgcore_tsctsf_pcf_app_session_delete_reconciled_total",
        "Npcf_PolicyAuthorization_Deletes that outlived their retry budget, by how the \
         reconciler ended them",
        &["result"],
    );

/// The parked resource ids, oldest first. Their `appSessionId`s stay in
/// `actuation`'s map, which is what a retried Delete sends.
fn pending() -> &'static Mutex<VecDeque<Parked>> {
    static PENDING: Mutex<VecDeque<Parked>> = Mutex::new(VecDeque::new());
    &PENDING
}

/// One parked resource, and when it was first parked (#1961).
#[derive(Debug, Clone)]
struct Parked {
    resource_id: String,
    /// Wall-clock, so a test can set it back past [`MAX_AGE`].
    since: std::time::SystemTime,
}

/// #1961: how long an entry stays parked before it is given up (`expired`): a
/// peer that has not answered for a day is gone (decommissioned), not
/// restarting, so its entries end rather than wait to be evicted.
pub const MAX_AGE: Duration = Duration::from_secs(24 * 3600);

/// #1961 (the #1954 / #1972 pattern): the first wait before a peer whose
/// request failed is tried again, doubled after each further failure up to
/// [`BACKOFF_MAX`], and cleared by a success. A peer that is backing off is
/// skipped for the rest of the pass and for later passes until its wait ends,
/// so a blackholed peer costs one request timeout per backoff period and
/// cannot starve the entries for healthy peers behind it.
#[cfg(not(test))]
pub const BACKOFF_BASE: Duration = Duration::from_secs(30);
#[cfg(test)]
pub const BACKOFF_BASE: Duration = Duration::from_millis(300);
/// The longest a failing peer is left alone between attempts.
pub const BACKOFF_MAX: Duration = Duration::from_secs(600);

/// Per peer: its backoff (#1994: the shared one), guarded like the parked set.
static BACKOFF: nextgcore_core::backoff::PeerBackoff =
    nextgcore_core::backoff::PeerBackoff::new(BACKOFF_BASE, BACKOFF_MAX);

/// The peer every Delete goes to: the one resolved PCF.
const PCF_PEER: &str = "pcf";

/// Park `resource_id` for the reconciler; a resource already parked is not added
/// twice.
pub fn park(resource_id: String) {
    let evicted = {
        let Ok(mut set) = pending().lock() else {
            return;
        };
        if set.iter().any(|p| p.resource_id == resource_id) {
            return;
        }
        log::warn!(
            "Npcf_PolicyAuthorization_Delete for {resource_id} is parked; it is retried every \
             {RECONCILE_PERIOD:?}"
        );
        set.push_back(Parked {
            resource_id,
            since: std::time::SystemTime::now(),
        });
        evict(&mut set)
    };
    for old in evicted {
        abandon(&old);
    }
}

/// Evict down to [`MAX_PENDING`], the oldest by park time first, wherever
/// rotation has put it (#1994: it popped the front, which rotation makes the
/// next to be tried, not the oldest). Returns the evicted resource ids, for
/// [`abandon`] once the set's lock is released.
fn evict(set: &mut VecDeque<Parked>) -> Vec<String> {
    nextgcore_core::backoff::evict_oldest(set, MAX_PENDING, |p| p.since)
        .into_iter()
        .map(|p| p.resource_id)
        .collect()
}

/// #1994: forget the PCF's backoff once nothing is parked for it, so the map
/// does not keep it for good.
fn prune_backoff(set: &VecDeque<Parked>) {
    BACKOFF.retain(|peer| peer != PCF_PEER || !set.is_empty());
}

fn abandon(resource_id: &str) {
    let app_session_id = crate::actuation::forget_app_session(resource_id);
    log::error!(
        "abandoning the Npcf_PolicyAuthorization_Delete for {resource_id} \
         (appSessionId={app_session_id:?}): {MAX_PENDING} deletes are already pending"
    );
    RECONCILED.inc(&["abandoned"]);
}

/// How many Deletes are parked: the
/// `nextgcore_tsctsf_pcf_app_session_deletes_pending` gauge.
pub fn pending_count() -> usize {
    pending().lock().map(|s| s.len()).unwrap_or(0)
}

/// The longest one pass sends for. A pass against a blackholed PCF costs a client
/// timeout per resource, so past this the rest are re-parked for the next pass.
#[cfg(not(test))]
pub const MAX_PASS: Duration = Duration::from_secs(30);
#[cfg(test)]
pub const MAX_PASS: Duration = Duration::from_millis(500);

/// One reconcile pass: retry parked Deletes, oldest first, for at most
/// [`MAX_PASS`]. A 2xx or 404 (or no `appSessionId` left to send) ends one; one
/// older than [`MAX_AGE`] ends as `expired`.
///
/// #1961: once a Delete fails the PCF backs off and the rest are not tried this
/// pass (nor until the backoff ends); a resource tried and failed goes to the
/// BACK of the queue, one not reached keeps its place at the FRONT. Returns how
/// many the PCF accepted.
///
/// Unlike mbsmfd's, a parked id cannot come back into use: resource ids are
/// UUIDs, never reissued.
pub async fn reconcile_once() -> usize {
    let batch: Vec<Parked> = match pending().lock() {
        Ok(mut set) => set.drain(..).collect(),
        Err(_) => return 0,
    };
    let deadline = tokio::time::Instant::now() + MAX_PASS;
    let mut deleted = 0;
    let mut untried = Vec::new();
    let mut failed = Vec::new();
    let mut expired = Vec::new();
    for p in batch {
        if p.since.elapsed().unwrap_or_default() > MAX_AGE {
            expired.push(p.resource_id);
            continue;
        }
        if tokio::time::Instant::now() >= deadline || BACKOFF.backing_off(PCF_PEER) {
            untried.push(p);
            continue;
        }
        match crate::actuation::delete_once_for_reconciler(&p.resource_id).await {
            crate::actuation::DeleteOutcome::Deleted => {
                BACKOFF.note_success(PCF_PEER);
                log::info!(
                    "reconciler deleted the PCF app session of {}",
                    p.resource_id
                );
                RECONCILED.inc(&["deleted"]);
                deleted += 1;
            }
            crate::actuation::DeleteOutcome::NothingRecorded => {}
            crate::actuation::DeleteOutcome::Failed => {
                BACKOFF.note_failure(PCF_PEER);
                failed.push(p);
            }
        }
    }
    let mut evicted = Vec::new();
    if let Ok(mut set) = pending().lock() {
        for p in untried.into_iter().rev() {
            if !set.iter().any(|q| q.resource_id == p.resource_id) {
                set.push_front(p);
            }
        }
        for p in failed {
            if !set.iter().any(|q| q.resource_id == p.resource_id) {
                set.push_back(p);
            }
        }
        evicted = evict(&mut set);
        prune_backoff(&set);
    }
    for old in evicted {
        abandon(&old);
    }
    for resource_id in expired {
        let app_session_id = crate::actuation::forget_app_session(&resource_id);
        log::error!(
            "the Npcf_PolicyAuthorization_Delete for {resource_id} \
             (appSessionId={app_session_id:?}) expired after {MAX_AGE:?}"
        );
        RECONCILED.inc(&["expired"]);
    }
    deleted
}

/// Run [`reconcile_once`] every [`RECONCILE_PERIOD`] for the life of the process.
pub fn spawn_reconciler() -> tokio::task::JoinHandle<()> {
    tokio::spawn(async {
        let mut timer = tokio::time::interval(RECONCILE_PERIOD);
        timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // The first tick is immediate; consume it so the first pass is a period in.
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
        "nextgcore_tsctsf_pcf_app_session_deletes_pending",
        "gauge",
        "Npcf_PolicyAuthorization_Deletes parked for the reconciler",
    );
    let _ = writeln!(
        out,
        "nextgcore_tsctsf_pcf_app_session_deletes_pending {}",
        pending_count()
    );
    RECONCILED.render(out);
}

#[cfg(test)]
pub fn clear_for_test() {
    if let Ok(mut set) = pending().lock() {
        set.clear();
    }
    BACKOFF.clear();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lock() -> std::sync::MutexGuard<'static, ()> {
        crate::context::PROCESS_STATE_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }

    fn pass_1994() -> usize {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime")
            .block_on(reconcile_once())
    }

    fn held_1994() -> Vec<String> {
        pending()
            .lock()
            .unwrap()
            .iter()
            .map(|p| p.resource_id.clone())
            .collect()
    }

    /// #1994: eviction takes the oldest wherever rotation has put it. A failed
    /// Delete goes to the back, so the front is the next to be tried, not the
    /// oldest.
    ///
    /// REVERT-VERIFIED: with `evict` popping the front, as before, this fails:
    /// the younger front entry is evicted and the oldest kept.
    #[test]
    fn eviction_takes_the_oldest_after_rotation_1994() {
        let _g = lock();
        clear_for_test();
        crate::actuation::clear_app_sessions_for_test();
        for n in 0..MAX_PENDING {
            park(format!("r-{n}"));
        }
        // A pass tried the oldest and it failed: it is at the back now.
        {
            let mut set = pending().lock().unwrap();
            let oldest = set.pop_front().expect("parked");
            set.push_back(oldest);
        }
        park(format!("r-{MAX_PENDING}"));
        let held = held_1994();
        clear_for_test();

        assert_eq!(held.len(), MAX_PENDING);
        assert!(!held.contains(&"r-0".to_string()), "the oldest went");
        assert!(held.contains(&"r-1".to_string()), "not the front");
    }

    /// #1994: the PCF's backoff is kept while a Delete is parked for it, and
    /// forgotten by the first pass with nothing parked.
    ///
    /// REVERT-VERIFIED: with `prune_backoff` a no-op, this fails: the backoff
    /// outlives the parked set.
    #[test]
    fn the_pcf_backoff_is_pruned_once_nothing_is_parked_1994() {
        let _g = lock();
        clear_for_test();
        BACKOFF.note_failure(PCF_PEER);
        // Backing off, so not contacted: it stays parked.
        park("r-1994".to_string());
        pass_1994();
        let while_parked = BACKOFF.current(PCF_PEER);
        pending().lock().unwrap().clear();
        pass_1994();
        let after = BACKOFF.current(PCF_PEER);
        clear_for_test();

        assert_eq!(while_parked, Some(BACKOFF_BASE), "still parked: kept");
        assert_eq!(after, None, "nothing parked: pruned");
    }

    /// #1817 bound: parking past [`MAX_PENDING`] evicts the oldest, forgets its
    /// `appSessionId` and counts it abandoned; a duplicate is not parked twice.
    ///
    /// REVERT-VERIFIED: with the eviction removed, the set grows to MAX_PENDING + 1.
    #[test]
    fn the_parked_set_is_bounded_and_evicts_the_oldest_1817() {
        let _g = lock();
        clear_for_test();
        crate::actuation::clear_app_sessions_for_test();
        crate::actuation::record_app_session_for_test("r-0", "asc-0");
        let before = RECONCILED.get(&["abandoned"]);
        for n in 0..MAX_PENDING {
            park(format!("r-{n}"));
        }
        park("r-0".to_string());
        assert_eq!(
            pending_count(),
            MAX_PENDING,
            "a duplicate is not parked twice"
        );
        park(format!("r-{MAX_PENDING}"));
        assert_eq!(pending_count(), MAX_PENDING);
        assert_eq!(RECONCILED.get(&["abandoned"]), before + 1);
        assert_eq!(
            pending()
                .lock()
                .unwrap()
                .front()
                .map(|p| p.resource_id.clone())
                .as_deref(),
            Some("r-1")
        );
        assert_eq!(
            crate::actuation::app_session_for("r-0"),
            None,
            "the evicted resource's appSessionId is forgotten with it"
        );
        clear_for_test();
    }

    /// #1961: tsctsf sends every Delete to its one PCF, so once one fails the
    /// rest are not tried in that pass (nor while the PCF backs off): a dead PCF
    /// costs one attempt per backoff period, not one timeout per resource. The
    /// tried one goes to the BACK; the others keep their order at the front.
    /// REVERT-VERIFIED: with the old order restored (no backoff, everything back
    /// at the front), every parked Delete is attempted each pass and the
    /// one-attempt assertion fails.
    #[tokio::test]
    #[allow(clippy::await_holding_lock)] // the crate's std test lock, held across the pass
    async fn a_failing_pcf_costs_one_attempt_per_pass_1961() {
        let _g = lock();
        clear_for_test();
        crate::actuation::clear_app_sessions_for_test();
        for n in 0..3 {
            crate::actuation::record_app_session_for_test(&format!("r1961-{n}"), "asc");
            park(format!("r1961-{n}"));
        }
        // A PCF on a port nothing listens on: every Delete fails.
        std::env::set_var("PCF_URI", "http://127.0.0.1:9");
        reconcile_once().await;
        std::env::remove_var("PCF_URI");
        let order: Vec<String> = pending()
            .lock()
            .unwrap()
            .iter()
            .map(|p| p.resource_id.clone())
            .collect();
        let attempts = (0..3)
            .filter(|n| crate::actuation::app_session_for(&format!("r1961-{n}")).is_some())
            .count();
        clear_for_test();
        crate::actuation::clear_app_sessions_for_test();
        assert_eq!(attempts, 3, "a failed Delete keeps its appSessionId");
        assert_eq!(
            order,
            ["r1961-1", "r1961-2", "r1961-0"],
            "one attempt: the tried one goes to the back, the rest keep their place"
        );
    }

    /// #1961: a Delete parked longer than [`MAX_AGE`] ends as `expired` and its
    /// `appSessionId` is forgotten. REVERT-VERIFIED: with the age check removed
    /// it stays parked.
    #[tokio::test]
    #[allow(clippy::await_holding_lock)] // the crate's std test lock, held across the pass
    async fn a_delete_older_than_max_age_expires_1961() {
        let _g = lock();
        clear_for_test();
        crate::actuation::clear_app_sessions_for_test();
        crate::actuation::record_app_session_for_test("r1961-old", "asc-old");
        park("r1961-old".to_string());
        pending().lock().unwrap()[0].since =
            std::time::SystemTime::now() - MAX_AGE - Duration::from_secs(1);
        let before = RECONCILED.get(&["expired"]);
        reconcile_once().await;
        let expired = RECONCILED.get(&["expired"]) - before;
        let left = pending_count();
        let forgotten = crate::actuation::app_session_for("r1961-old").is_none();
        clear_for_test();
        assert_eq!((expired, left, forgotten), (1, 0, true));
    }

    /// The gauge and the counter are on `/metrics`.
    #[test]
    fn the_reconciler_families_render_1817() {
        let _g = lock();
        clear_for_test();
        park("a".to_string());
        park("b".to_string());
        let mut out = String::new();
        render(&mut out);
        assert_eq!(
            nextgcore_metrics::nf::sample_value(
                &out,
                "nextgcore_tsctsf_pcf_app_session_deletes_pending"
            ),
            Some(2.0)
        );
        assert!(
            out.contains("# TYPE nextgcore_tsctsf_pcf_app_session_delete_reconciled_total counter")
        );
        clear_for_test();
    }
}
