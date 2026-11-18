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
/// Deletes the reconciler delivered (`deleted`) or evicted at the bound
/// (`abandoned`).
pub static RECONCILED: nextgcore_metrics::nf::CounterFamily =
    nextgcore_metrics::nf::CounterFamily::new(
        "nextgcore_tsctsf_pcf_app_session_delete_reconciled_total",
        "Npcf_PolicyAuthorization_Deletes that outlived their retry budget, by how the \
         reconciler ended them",
        &["result"],
    );

/// The parked resource ids, oldest first. Their `appSessionId`s stay in
/// `actuation`'s map, which is what a retried Delete sends.
fn pending() -> &'static Mutex<VecDeque<String>> {
    static PENDING: Mutex<VecDeque<String>> = Mutex::new(VecDeque::new());
    &PENDING
}

/// Park `resource_id` for the reconciler; a resource already parked is not added
/// twice.
pub fn park(resource_id: String) {
    let evicted = {
        let Ok(mut set) = pending().lock() else {
            return;
        };
        if set.contains(&resource_id) {
            return;
        }
        let evicted = if set.len() >= MAX_PENDING {
            set.pop_front()
        } else {
            None
        };
        log::warn!(
            "Npcf_PolicyAuthorization_Delete for {resource_id} is parked; it is retried every \
             {RECONCILE_PERIOD:?}"
        );
        set.push_back(resource_id);
        evicted
    };
    if let Some(old) = evicted {
        abandon(&old);
    }
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

/// One reconcile pass: retry every parked Delete once. A 2xx or 404 (or no
/// `appSessionId` left to send) ends it; a failure re-parks it, ahead of anything
/// parked meanwhile. Returns how many the PCF accepted.
pub async fn reconcile_once() -> usize {
    let batch: Vec<String> = match pending().lock() {
        Ok(mut set) => set.drain(..).collect(),
        Err(_) => return 0,
    };
    let mut deleted = 0;
    let mut still = Vec::new();
    for resource_id in batch {
        match crate::actuation::delete_once_for_reconciler(&resource_id).await {
            crate::actuation::DeleteOutcome::Deleted => {
                log::info!("reconciler deleted the PCF app session of {resource_id}");
                RECONCILED.inc(&["deleted"]);
                deleted += 1;
            }
            crate::actuation::DeleteOutcome::NothingRecorded => {}
            crate::actuation::DeleteOutcome::Failed => still.push(resource_id),
        }
    }
    let mut evicted = Vec::new();
    if !still.is_empty() {
        if let Ok(mut set) = pending().lock() {
            for resource_id in still.into_iter().rev() {
                if !set.contains(&resource_id) {
                    set.push_front(resource_id);
                }
            }
            while set.len() > MAX_PENDING {
                evicted.extend(set.pop_front());
            }
        }
    }
    for old in evicted {
        abandon(&old);
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
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lock() -> std::sync::MutexGuard<'static, ()> {
        crate::context::PROCESS_STATE_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner())
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
            pending().lock().unwrap().front().map(String::as_str),
            Some("r-1")
        );
        assert_eq!(
            crate::actuation::app_session_for("r-0"),
            None,
            "the evicted resource's appSessionId is forgotten with it"
        );
        clear_for_test();
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
